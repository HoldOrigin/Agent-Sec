package collector

import (
	"sort"
	"sync"
	"time"
)

type RoutedEvent struct {
	Event    map[string]any
	Priority UploadPriority
}

type EventRouter interface {
	Process(event map[string]any, now time.Time) []RoutedEvent
	Flush(now time.Time, force bool) []RoutedEvent
}

type UploadRouterConfig struct {
	BufferTTL              time.Duration
	BufferMaxBytes         int64
	BufferMaxBytesPerScope int64
	AggregateWindow        time.Duration
	MaxAggregateKeys       int
	PostAlertWindow        time.Duration
}

type UploadRouter struct {
	mu              sync.Mutex
	detection       DetectionPolicy
	policy          UploadPolicy
	buffer          *RollingBuffer
	aggregator      *EventAggregator
	localAggregator *EventAggregator
	metrics         *Metrics
	postAlertWindow time.Duration
	alertedScopes   map[string]time.Time
}

func NewUploadRouter(config UploadRouterConfig, detection DetectionPolicy, policy UploadPolicy, metrics *Metrics) *UploadRouter {
	if detection == nil {
		detection = NewDefaultDetectionPolicy()
	}
	if policy == nil {
		policy = NewDefaultUploadPolicy()
	}
	if metrics == nil {
		metrics = &Metrics{}
	}
	if config.PostAlertWindow <= 0 {
		config.PostAlertWindow = 2 * time.Minute
	}
	return &UploadRouter{
		detection:       detection,
		policy:          policy,
		buffer:          NewRollingBuffer(config.BufferTTL, config.BufferMaxBytes, config.BufferMaxBytesPerScope),
		aggregator:      NewEventAggregator(config.AggregateWindow, config.MaxAggregateKeys),
		localAggregator: NewEventAggregator(config.AggregateWindow, config.MaxAggregateKeys),
		metrics:         metrics,
		postAlertWindow: config.PostAlertWindow,
		alertedScopes:   map[string]time.Time{},
	}
}

func (router *UploadRouter) Process(event map[string]any, now time.Time) []RoutedEvent {
	router.mu.Lock()
	defer router.mu.Unlock()
	router.expireAlertsLocked(now)
	detection := router.detection.Evaluate(event)
	if detection.Alert {
		router.metrics.LocalAlerts.Add(1)
	}
	annotateDetection(event, detection)
	decision := router.policy.Decide(event)
	annotateUpload(event, decision)
	scope := eventScopeKey(event)

	switch decision.Mode {
	case UploadAlways:
		router.metrics.UploadAlways.Add(1)
		result := []RoutedEvent{}
		if decision.PromoteContext {
			router.alertedScopes[scope] = now.Add(router.postAlertWindow)
			promoted, evicted := router.buffer.Promote(scope, now)
			router.metrics.BufferEvicted.Add(uint64(evicted))
			router.metrics.ContextPromoted.Add(uint64(len(promoted)))
			for _, contextEvent := range promoted {
				metadata := eventMap(contextEvent, "metadata")
				metadata["upload_mode"] = string(UploadAlways)
				metadata["upload_priority"] = string(PriorityHigh)
				metadata["upload_reason"] = "pre_alert_context"
				metadata["promoted_context"] = true
				result = append(result, RoutedEvent{Event: contextEvent, Priority: PriorityHigh})
			}
		}
		result = append(result, RoutedEvent{Event: event, Priority: decision.Priority})
		sortRoutedEvents(result)
		router.updateGaugesLocked(now)
		return result
	case UploadOnAlert:
		if expires, active := router.alertedScopes[scope]; active && expires.After(now) {
			router.metrics.UploadAlways.Add(1)
			metadata := eventMap(event, "metadata")
			metadata["upload_mode"] = string(UploadAlways)
			metadata["upload_priority"] = string(PriorityHigh)
			metadata["upload_reason"] = "post_alert_context"
			metadata["promoted_context"] = true
			router.updateGaugesLocked(now)
			return []RoutedEvent{{Event: event, Priority: PriorityHigh}}
		}
		router.metrics.UploadOnAlertBuffered.Add(1)
		evicted := router.buffer.Add(event, now, true)
		router.metrics.BufferEvicted.Add(uint64(evicted))
	case UploadAggregate:
		router.metrics.AggregateInput.Add(1)
		emitted := router.aggregator.Add(event, now)
		router.metrics.AggregateOutput.Add(uint64(len(emitted)))
		result := routeNormal(emitted)
		router.updateGaugesLocked(now)
		return result
	case UploadLocalOnly:
		router.metrics.UploadLocalOnly.Add(1)
		summaries := router.localAggregator.Add(event, now)
		router.retainLocalSummariesLocked(summaries, now)
	}
	router.updateGaugesLocked(now)
	return nil
}

func (router *UploadRouter) Flush(now time.Time, force bool) []RoutedEvent {
	router.mu.Lock()
	defer router.mu.Unlock()
	router.expireAlertsLocked(now)
	events := router.aggregator.Flush(now, force)
	localSummaries := router.localAggregator.Flush(now, force)
	if !force {
		router.retainLocalSummariesLocked(localSummaries, now)
	}
	router.metrics.AggregateOutput.Add(uint64(len(events)))
	router.updateGaugesLocked(now)
	return routeNormal(events)
}

func (router *UploadRouter) updateGaugesLocked(now time.Time) {
	bytes, entries, evicted := router.buffer.Stats(now)
	router.metrics.BufferEvicted.Add(uint64(evicted))
	router.metrics.BufferBytes.Store(bytes)
	router.metrics.BufferEntries.Store(int64(entries))
	router.metrics.AggregateKeys.Store(int64(router.aggregator.Len() + router.localAggregator.Len()))
	router.metrics.ActiveAlertScopes.Store(int64(len(router.alertedScopes)))
}

func (router *UploadRouter) retainLocalSummariesLocked(events []map[string]any, now time.Time) {
	router.metrics.LocalOnlySummaries.Add(uint64(len(events)))
	for _, event := range events {
		metadata := eventMap(event, "metadata")
		metadata["upload_mode"] = string(UploadLocalOnly)
		metadata["upload_priority"] = string(PriorityNormal)
		metadata["upload_reason"] = "local_only_summary"
		evicted := router.buffer.Add(event, now, false)
		router.metrics.BufferEvicted.Add(uint64(evicted))
	}
}

func (router *UploadRouter) expireAlertsLocked(now time.Time) {
	for scope, expires := range router.alertedScopes {
		if !expires.After(now) {
			delete(router.alertedScopes, scope)
		}
	}
}

func annotateUpload(event map[string]any, decision UploadDecision) {
	metadata := eventMap(event, "metadata")
	metadata["upload_mode"] = string(decision.Mode)
	metadata["upload_priority"] = string(decision.Priority)
	metadata["upload_reason"] = decision.Reason
	if decision.PromoteContext {
		metadata["local_alert"] = true
	}
	event["metadata"] = metadata
}

func routeNormal(events []map[string]any) []RoutedEvent {
	result := make([]RoutedEvent, 0, len(events))
	for _, event := range events {
		result = append(result, RoutedEvent{Event: event, Priority: PriorityNormal})
	}
	return result
}

func sortRoutedEvents(events []RoutedEvent) {
	sort.SliceStable(events, func(left, right int) bool {
		return eventTimestamp(events[left].Event).Before(eventTimestamp(events[right].Event))
	})
}

func eventTimestamp(event map[string]any) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, eventString(event, "timestamp"))
	if err != nil {
		return time.Time{}
	}
	return parsed
}
