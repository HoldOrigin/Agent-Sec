package tools

import (
	"context"
	"encoding/json"
	"sync"

	"sentinel/internal/agentdomain"
)

type EventRepository interface {
	QueryEvents(ctx context.Context, scope domain.Scope, kinds []domain.EventKind, offset, limit int) ([]domain.Event, bool, error)
}

type EventAdapter struct{ Repository EventRepository }

func (a EventAdapter) Query(ctx context.Context, spec Spec, args map[string]any, invocation InvocationContext) (AdapterResult, *ToolError) {
	limit := int(args["limit"].(int64))
	offset, _ := args["_offset"].(int)
	kinds := spec.EventKinds
	if requested, ok := args["event_types"].([]string); ok {
		kinds = make([]domain.EventKind, len(requested))
		for i := range requested {
			kinds[i] = domain.EventKind(requested[i])
		}
	}
	events := []domain.Event{}
	more, scanned, capped := true, 0, false
	ref, _ := args["entity_ref"].(string)
	relation, _ := args["relation"].(string)
	entity, filterEntity := invocation.Entities.Resolve(ref)
	if ref == "scope" {
		filterEntity = false
	}
	for more && len(events) < limit && scanned < 500 {
		chunkLimit := limit
		if chunkLimit < 50 {
			chunkLimit = 50
		}
		chunk, hasMore, err := a.Repository.QueryEvents(ctx, invocation.Scope, kinds, offset+scanned, chunkLimit)
		if err != nil {
			return AdapterResult{}, reject(ErrSourceUnavailable, "", "事件数据源查询失败", true)
		}
		for index, event := range chunk {
			scanned++
			if !filterEntity || eventMatchesEntity(event, entity, relation) {
				events = append(events, event)
				if len(events) == limit {
					more = index+1 < len(chunk) || hasMore
					break
				}
			}
		}
		if len(events) < limit {
			more = hasMore
		}
		if len(chunk) == 0 {
			break
		}
	}
	if more && scanned >= 500 {
		capped = true
	}
	status := StatusOK
	if len(events) == 0 {
		status = StatusEmpty
	}
	warnings := []string{}
	if capped {
		warnings = append(warnings, "单次查询最多扫描500条候选事件，请使用游标继续")
	}
	return AdapterResult{Events: events, NextOffset: offset + scanned, HasMore: more, Status: status,
		Coverage: Coverage{QueryComplete: !more, Truncated: more, TelemetryState: "UNKNOWN", Source: "normalized_events", Warnings: warnings}}, nil
}

func eventMatchesEntity(event domain.Event, entity domain.Entity, relation string) bool {
	switch entity.Type {
	case domain.EntityProcess:
		if relation == "parents" {
			var attributes map[string]any
			if json.Unmarshal(entity.Attributes, &attributes) != nil {
				return false
			}
			parent, _ := attributes["parent_process_id"].(string)
			return parent != "" && event.ProcessID == parent
		}
		if relation == "children" {
			return event.ParentProcess == entity.ID
		}
		return event.ProcessID == entity.ID
	case domain.EntitySession:
		return event.SessionID == entity.ID
	case domain.EntityIdentity:
		return event.IdentityID == entity.ID
	case domain.EntityHost:
		return event.HostID == entity.ID
	case domain.EntityContainer:
		return event.ContainerID == entity.ID
	case domain.EntityFile, domain.EntityIP, domain.EntityDomain, domain.EntityRequest, domain.EntityWorkload:
		var details map[string]any
		if json.Unmarshal(event.Details, &details) != nil {
			return false
		}
		for _, key := range []string{"file_ref", "source_ip_ref", "destination_ip_ref", "domain_ref", "request_ref", "workload_ref"} {
			if details[key] == entity.ID {
				return true
			}
		}
	}
	return false
}

type MemoryEvents struct {
	mu     sync.RWMutex
	events []domain.Event
}

func NewMemoryEvents(events ...domain.Event) *MemoryEvents {
	return &MemoryEvents{events: append([]domain.Event(nil), events...)}
}
func (m *MemoryEvents) Add(event domain.Event) error {
	if err := event.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return nil
}
func (m *MemoryEvents) QueryEvents(_ context.Context, scope domain.Scope, kinds []domain.EventKind, offset, limit int) ([]domain.Event, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	allowed := map[domain.EventKind]struct{}{}
	for _, kind := range kinds {
		allowed[kind] = struct{}{}
	}
	matched := []domain.Event{}
	for _, event := range m.events {
		if _, ok := allowed[event.Kind]; ok && scope.Contains(event) {
			matched = append(matched, event)
		}
	}
	if offset > len(matched) {
		offset = len(matched)
	}
	end := offset + limit
	if end > len(matched) {
		end = len(matched)
	}
	return append([]domain.Event(nil), matched[offset:end]...), end < len(matched), nil
}

type UnsupportedAdapter struct{ Message string }

func (a UnsupportedAdapter) Query(context.Context, Spec, map[string]any, InvocationContext) (AdapterResult, *ToolError) {
	message := a.Message
	if message == "" {
		message = "数据源未配置"
	}
	return AdapterResult{}, reject(ErrSourceUnavailable, "", message, false)
}
