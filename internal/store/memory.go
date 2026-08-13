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

func NewMemory() *Memory {
	s := &Memory{}
	s.Reset()
	return s
}

func (s *Memory) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = make(map[string]model.RuntimeEvent)
	s.behaviors = make(map[string]model.Behavior)
	s.alerts = make(map[string]model.Alert)
	s.incidents = make(map[string]model.Incident)
}

func (s *Memory) AddEvent(event model.RuntimeEvent) model.RuntimeEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events[event.EventID] = event
	return event
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

func (s *Memory) ReplaceBehaviors(items []model.Behavior) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.behaviors = make(map[string]model.Behavior, len(items))
	for _, item := range items {
		s.behaviors[item.BehaviorID] = item
	}
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

func (s *Memory) AddAlert(alert model.Alert) model.Alert {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, existing := range s.alerts {
		if existing.CorrelationKey != alert.CorrelationKey || existing.Status == "closed" {
			continue
		}
		existing.RuleIDs = unique(append(existing.RuleIDs, alert.RuleIDs...))
		existing.EventIDs = unique(append(existing.EventIDs, alert.EventIDs...))
		if severityRank(alert.Severity) > severityRank(existing.Severity) {
			existing.Severity = alert.Severity
		}
		existing.UpdatedAt = time.Now().UTC()
		s.alerts[id] = existing
		return existing
	}
	s.alerts[alert.AlertID] = alert
	return alert
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

func (s *Memory) AddIncident(incident model.Incident) model.Incident {
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
	return incident
}

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
