package store

import (
	"sort"
	"sync"
	"time"

	"sentinel/internal/model"
)

type Memory struct {
	mu        sync.RWMutex
	events    map[string]model.RuntimeEvent
	behaviors map[string]model.Behavior
	alerts    map[string]model.Alert
	incidents map[string]model.Incident
}

// Repository is the storage boundary shared by the HTTP service, the
// deterministic investigator and the AI runtime. Read methods return an
// in-process snapshot; mutating methods return errors so a durable backend can
// fail closed instead of silently losing security evidence.
type Repository interface {
	Reset() error
	AddEvent(model.RuntimeEvent) (model.RuntimeEvent, error)
	Events() []model.RuntimeEvent
	Event(string) (model.RuntimeEvent, bool)
	ReplaceBehaviors([]model.Behavior) error
	Behaviors() []model.Behavior
	AddAlert(model.Alert) (model.Alert, error)
	Alerts() []model.Alert
	Alert(string) (model.Alert, bool)
	AddIncident(model.Incident) (model.Incident, error)
	Incident(string) (model.Incident, bool)
	Incidents() []model.Incident
	RelatedEvents(model.RuntimeEvent, time.Duration) []model.RuntimeEvent
	Close() error
	Name() string
}

func NewMemory() *Memory {
	s := &Memory{}
	s.reset()
	return s
}

func (s *Memory) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = make(map[string]model.RuntimeEvent)
	s.behaviors = make(map[string]model.Behavior)
	s.alerts = make(map[string]model.Alert)
	s.incidents = make(map[string]model.Incident)
}

func (s *Memory) Reset() error {
	s.reset()
	return nil
}

func (s *Memory) AddEvent(event model.RuntimeEvent) (model.RuntimeEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events[event.EventID] = event
	return event, nil
}

func (s *Memory) Events() []model.RuntimeEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]model.RuntimeEvent, 0, len(s.events))
	for _, event := range s.events {
		result = append(result, event)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Timestamp.Before(result[j].Timestamp) })
	return result
}

func (s *Memory) Event(id string) (model.RuntimeEvent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	event, ok := s.events[id]
	return event, ok
}

func (s *Memory) ReplaceBehaviors(items []model.Behavior) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.behaviors = make(map[string]model.Behavior, len(items))
	for _, item := range items {
		s.behaviors[item.BehaviorID] = item
	}
	return nil
}

func (s *Memory) Behaviors() []model.Behavior {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]model.Behavior, 0, len(s.behaviors))
	for _, item := range s.behaviors {
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Timestamp.Before(result[j].Timestamp) })
	return result
}

func (s *Memory) AddAlert(alert model.Alert) (model.Alert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, existing := range s.alerts {
		if existing.CorrelationKey != alert.CorrelationKey || existing.Status == "closed" {
			continue
		}
		existing.RuleIDs = unique(append(existing.RuleIDs, alert.RuleIDs...))
		existing.EventIDs = unique(append(existing.EventIDs, alert.EventIDs...))
		if alert.Source == "collector" || existing.Source == "" {
			existing.Source = alert.Source
			existing.Title = firstNonEmpty(alert.Title, existing.Title)
			existing.Description = firstNonEmpty(alert.Description, existing.Description)
			existing.HostID = firstNonEmpty(alert.HostID, existing.HostID)
			existing.ContainerID = firstNonEmpty(alert.ContainerID, existing.ContainerID)
		}
		if severityRank(alert.Severity) > severityRank(existing.Severity) {
			existing.Severity = alert.Severity
		}
		existing.UpdatedAt = time.Now().UTC()
		s.alerts[id] = existing
		return existing, nil
	}
	s.alerts[alert.AlertID] = alert
	return alert, nil
}

func (s *Memory) Alerts() []model.Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]model.Alert, 0, len(s.alerts))
	for _, item := range s.alerts {
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.After(result[j].CreatedAt) })
	return result
}

func (s *Memory) Alert(id string) (model.Alert, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	alert, ok := s.alerts[id]
	return alert, ok
}

func (s *Memory) AddIncident(incident model.Incident) (model.Incident, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if prior, ok := s.incidents[incident.IncidentID]; ok {
		incident.CreatedAt = prior.CreatedAt
	}
	if incident.CreatedAt.IsZero() {
		incident.CreatedAt = time.Now().UTC()
	}
	incident.UpdatedAt = time.Now().UTC()
	s.incidents[incident.IncidentID] = incident
	return incident, nil
}

func (s *Memory) Close() error { return nil }
func (s *Memory) Name() string { return "memory" }

func (s *Memory) Incident(id string) (model.Incident, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	incident, ok := s.incidents[id]
	return incident, ok
}

func (s *Memory) Incidents() []model.Incident {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]model.Incident, 0, len(s.incidents))
	for _, item := range s.incidents {
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.After(result[j].CreatedAt) })
	return result
}

func (s *Memory) RelatedEvents(seed model.RuntimeEvent, window time.Duration) []model.RuntimeEvent {
	all := s.Events()
	result := make([]model.RuntimeEvent, 0)
	for _, event := range all {
		sameScope := event.Host == seed.Host && ((seed.ContainerID != "" && event.ContainerID == seed.ContainerID) || event.PID == seed.PID || event.PPID == seed.PID || seed.PPID == event.PID)
		delta := event.Timestamp.Sub(seed.Timestamp)
		if delta < 0 {
			delta = -delta
		}
		if sameScope && delta <= window {
			result = append(result, event)
		}
	}
	return result
}

func unique(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func severityRank(value string) int {
	return map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}[value]
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
