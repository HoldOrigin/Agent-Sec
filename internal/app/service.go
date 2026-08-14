package app

import (
	"fmt"
	"strings"
	"time"

	"sentinel/internal/behavior"
	"sentinel/internal/collection"
	"sentinel/internal/incident"
	"sentinel/internal/investigation"
	"sentinel/internal/model"
	"sentinel/internal/policy"
	"sentinel/internal/processor"
	"sentinel/internal/store"
)

type Service struct {
	Config     Config
	Store      *store.Memory
	Processor  *processor.Processor
	Behavior   *behavior.Engine
	Incident   *incident.Engine
	Collection *collection.Manager
	Policy     *policy.Engine
	Agent      *investigation.Agent
}
type PipelineResult struct {
	Events    []model.RuntimeEvent `json:"events"`
	Dropped   []map[string]string  `json:"dropped,omitempty"`
	Behaviors []model.Behavior     `json:"behaviors"`
	Incidents []model.Incident     `json:"incidents"`
	Processor model.ProcessResult  `json:"processor,omitempty"`
}

func New(config Config) *Service {
	s := &Service{Config: config, Store: store.NewMemory(), Processor: processor.New(config.FileCacheTTL), Behavior: behavior.New(), Incident: incident.New(config.CorrelationWindow), Collection: collection.New(config.InvestigationWindow), Policy: policy.New()}
	s.Agent = investigation.New(s.Store, s.Policy, config.MaxAgentSteps)
	return s
}
func (s *Service) Reset() { s.Store.Reset(); s.Processor.Reset(); s.Collection.Reset() }
func (s *Service) Ingest(input map[string]any, run bool) (PipelineResult, error) {
	processed, err := s.Processor.Process(input)
	if err != nil {
		return PipelineResult{}, err
	}
	events := []model.RuntimeEvent{}
	for _, event := range processed.Accepted {
		if err := validateEvent(event); err != nil {
			return PipelineResult{}, err
		}
		events = append(events, s.Store.AddEvent(event))
	}
	result := PipelineResult{Events: events, Processor: processed}
	if run {
		behaviors, incidents, err := s.RunPipeline()
		result.Behaviors = behaviors
		result.Incidents = incidents
		return result, err
	}
	return result, nil
}
func (s *Service) IngestMany(inputs []map[string]any, reset bool) (PipelineResult, error) {
	if reset {
		s.Reset()
	}
	result := PipelineResult{Events: []model.RuntimeEvent{}, Dropped: []map[string]string{}}
	for _, input := range inputs {
		item, err := s.Ingest(input, false)
		if err != nil {
			return PipelineResult{}, err
		}
		result.Events = append(result.Events, item.Events...)
		if item.Processor.Dropped != "" {
			result.Dropped = append(result.Dropped, map[string]string{"event_id": stringValue(input["event_id"]), "reason": item.Processor.Dropped})
		}
	}
	behaviors, incidents, err := s.RunPipeline()
	result.Behaviors = behaviors
	result.Incidents = incidents
	return result, err
}
func (s *Service) RunPipeline() ([]model.Behavior, []model.Incident, error) {
	events := s.Store.Events()
	behaviors := s.Behavior.Derive(events)
	s.Store.ReplaceBehaviors(behaviors)
	s.Collection.ObserveBehaviors(behaviors)
	for _, item := range behaviors {
		if item.Type != "LocalSecurityPolicyMatch" {
			continue
		}
		eventID := ""
		if len(item.Evidence) > 0 {
			eventID = item.Evidence[0]
		}
		now := item.Timestamp
		if now.IsZero() {
			now = time.Now().UTC()
		}
		severity := normalizedSeverity(detailString(item.Details, "severity"))
		ruleID := detailString(item.Details, "rule_id")
		if ruleID == "" {
			ruleID = "LOCAL-DETECTION"
		}
		s.Store.AddAlert(model.Alert{
			AlertID:        "alt-" + strings.TrimPrefix(item.BehaviorID, "beh-"),
			Title:          "Local runtime security policy matched",
			Severity:       severity,
			RuleIDs:        []string{ruleID},
			EventIDs:       append([]string{}, item.Evidence...),
			EventID:        eventID,
			CorrelationKey: item.CorrelationKey,
			Status:         "open",
			CreatedAt:      now,
			UpdatedAt:      now,
		})
	}
	correlated := s.Incident.Correlate(behaviors, events)
	s.Collection.ObserveIncidents(correlated)
	incidents := []model.Incident{}
	for _, base := range correlated {
		now := base.StartTime
		alert := s.Store.AddAlert(model.Alert{AlertID: "alt-" + strings.TrimPrefix(base.IncidentID, "inc-"), Title: "Web RCE Payload Execution Pattern", Severity: base.Severity, RuleIDs: []string{"PATTERN-WEB-RCE-001"}, EventIDs: []string{base.EvidenceEventIDs[0]}, EventID: base.EvidenceEventIDs[0], CorrelationKey: base.HostID + ":" + base.ContainerID, Status: "open", CreatedAt: now, UpdatedAt: now})
		base.AlertID = alert.AlertID
		investigated, err := s.Agent.Investigate(base)
		if err != nil {
			return nil, nil, err
		}
		incidents = append(incidents, investigated)
	}
	return behaviors, incidents, nil
}
func (s *Service) Investigate(id string) (model.Incident, error) {
	item, ok := s.Store.Incident(id)
	if !ok {
		return model.Incident{}, NewError(404, "Incident not found")
	}
	return s.Agent.Investigate(item)
}
func (s *Service) EvaluateAction(request policy.ActionRequest) (model.PolicyDecision, error) {
	if request.Action == "" {
		return model.PolicyDecision{}, NewError(400, "action is required")
	}
	return s.Policy.Evaluate(request), nil
}
func (s *Service) Summary() map[string]int {
	incidents := s.Store.Incidents()
	critical := 0
	approvals := 0
	for _, item := range incidents {
		if item.Risk == "critical" {
			critical++
		}
		for _, rec := range item.Recommendations {
			if rec.Policy.Decision == "require_approval" {
				approvals++
			}
		}
	}
	return map[string]int{"events": len(s.Store.Events()), "behaviors": len(s.Store.Behaviors()), "alerts": len(s.Store.Alerts()), "incidents": len(incidents), "critical": critical, "pending_approval": approvals}
}
func (s *Service) Metrics() string {
	stats := s.Processor.Stats()
	levels := map[string]int{"NORMAL": 0, "WATCH": 0, "INVESTIGATION": 0}
	for _, item := range s.Collection.List() {
		levels[item.Level]++
	}
	return fmt.Sprintf("# HELP runtime_events_received_total Runtime events received before filtering.\n# TYPE runtime_events_received_total counter\nruntime_events_received_total %d\n# HELP runtime_events_accepted_total Runtime events retained by the processor.\n# TYPE runtime_events_accepted_total counter\nruntime_events_accepted_total %d\nruntime_events_filtered_total %d\nruntime_events_deduplicated_total %d\nruntime_file_events_promoted_total %d\n# TYPE runtime_behaviors gauge\nruntime_behaviors %d\n# TYPE runtime_incidents gauge\nruntime_incidents %d\nruntime_collection_scopes{level=\"normal\"} %d\nruntime_collection_scopes{level=\"watch\"} %d\nruntime_collection_scopes{level=\"investigation\"} %d\n", stats.Received, stats.Accepted, stats.Filtered, stats.Deduplicated, stats.Promoted, len(s.Store.Behaviors()), len(s.Store.Incidents()), levels["NORMAL"], levels["WATCH"], levels["INVESTIGATION"])
}
func validateEvent(e model.RuntimeEvent) error {
	missing := []string{}
	if e.EventID == "" {
		missing = append(missing, "event_id")
	}
	if e.Type == "" {
		missing = append(missing, "type")
	}
	if e.Host == "" {
		missing = append(missing, "host")
	}
	if e.PID == 0 {
		missing = append(missing, "pid")
	}
	if e.Process == "" || e.Process == "." {
		missing = append(missing, "process")
	}
	if e.ProcessEntityID == "" {
		missing = append(missing, "process_entity_id")
	}
	if len(missing) > 0 {
		return NewError(400, "Missing event fields: "+strings.Join(missing, ", "))
	}
	return nil
}

type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string                  { return e.Message }
func NewError(status int, message string) error { return &Error{Status: status, Message: message} }
func stringValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func detailString(details map[string]any, key string) string {
	value, _ := details[key].(string)
	return value
}

func normalizedSeverity(value string) string {
	switch strings.ToLower(value) {
	case "low", "medium", "high", "critical":
		return strings.ToLower(value)
	default:
		return "high"
	}
}
