package collection

import (
	"sync"
	"time"

	"sentinel/internal/model"
)

type Manager struct {
	mu     sync.Mutex
	window time.Duration
	scopes map[string]model.CollectionPolicy
}

func New(window time.Duration) *Manager {
	return &Manager{window: window, scopes: map[string]model.CollectionPolicy{}}
}
func (m *Manager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scopes = map[string]model.CollectionPolicy{}
}
func (m *Manager) ObserveBehaviors(items []model.Behavior) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	for _, item := range items {
		if item.Type == "WebServerSpawnShell" {
			m.set(item.Scope, "WATCH", now.Add(m.window), "WebServerSpawnShell detected", now)
		}
	}
}
func (m *Manager) ObserveIncidents(items []model.Incident) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	for _, item := range items {
		m.set(model.Scope{HostID: item.HostID, ContainerID: item.ContainerID, Workload: item.Workload, Namespace: item.Namespace}, "INVESTIGATION", now.Add(m.window), "Incident "+item.IncidentID+" created", now)
	}
}
func (m *Manager) set(scope model.Scope, level string, expires time.Time, reason string, now time.Time) {
	key := scope.HostID + ":" + scope.ContainerID
	current, ok := m.scopes[key]
	rank := map[string]int{"NORMAL": 0, "WATCH": 1, "INVESTIGATION": 2}
	if !ok || rank[level] >= rank[current.Level] || (current.ExpiresAt != nil && current.ExpiresAt.Before(now)) {
		m.scopes[key] = model.CollectionPolicy{Scope: scope, Level: level, Reason: reason, ExpiresAt: &expires, UpdatedAt: now}
	}
}
func (m *Manager) List() []model.CollectionPolicy {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now().UTC()
	result := make([]model.CollectionPolicy, 0, len(m.scopes))
	for _, item := range m.scopes {
		if item.ExpiresAt != nil && item.ExpiresAt.Before(now) {
			item.Level = "NORMAL"
			item.Reason = "collection window expired"
		}
		result = append(result, item)
	}
	return result
}
