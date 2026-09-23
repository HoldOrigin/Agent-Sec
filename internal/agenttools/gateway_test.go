package tools

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"sentinel/internal/agentdomain"
)

func toolTestEvent(id, tenant, host string, kind domain.EventKind) domain.Event {
	now := time.Now().UTC()
	return domain.Event{ID: id, SchemaVersion: 1, TenantID: tenant, SensorID: "sensor-1", HostID: host,
		BootID: "boot-1", ProcessID: "proc-1", Kind: kind, Outcome: domain.OutcomeSuccess,
		ObservedAt: now, IngestedAt: now, Details: json.RawMessage(`{"executable":"/bin/sh"}`)}
}

func toolTestGateway(t *testing.T, adapter Adapter) (*Gateway, *Registry) {
	t.Helper()
	registry, err := NewRegistry(DefaultSpecs())
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := NewGateway(registry, map[string]Adapter{"events": adapter}, []byte("0123456789abcdef0123456789abcdef"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return gateway, registry
}

func toolInvocation(event domain.Event) InvocationContext {
	scope := domain.Scope{ID: "scope-1", TenantID: "tenant-1", Start: event.ObservedAt.Add(-time.Minute),
		End: event.ObservedAt.Add(time.Minute), AllowedHosts: []string{"host-1"}, SnapshotID: "snap-1"}
	allowed := map[string]struct{}{"process_events_query": {}}
	return InvocationContext{RunID: "run-1", TaskID: "T1", Scope: scope, AllowedTools: allowed,
		ActiveTools: allowed, Entities: NewMemoryEntities(), Budget: &CounterBudget{Limit: 10}}
}

func processRequest(cursor any) Request {
	return Request{CallID: randomID("call-"), Tool: "process_events_query", Arguments: map[string]any{
		"entity_ref": "scope", "relation": "tree", "event_types": []string{"PROCESS_EXEC"},
		"limit": 1, "cursor": cursor,
	}}
}

func TestDefaultRegistryContainsCompleteToolSet(t *testing.T) {
	registry, err := NewRegistry(DefaultSpecs())
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]struct{}{}
	for _, spec := range DefaultSpecs() {
		allowed[spec.Name] = struct{}{}
	}
	if got := len(registry.PublicCatalog(allowed)); got != 25 {
		t.Fatalf("got %d tools, want 25", got)
	}
}

func TestGatewayValidatesAndPagesEvidence(t *testing.T) {
	e1 := toolTestEvent("e1", "tenant-1", "host-1", domain.EventProcessExec)
	e2 := toolTestEvent("e2", "tenant-1", "host-1", domain.EventProcessExec)
	e2.ObservedAt = e1.ObservedAt.Add(time.Second)
	e2.IngestedAt = e2.ObservedAt
	gateway, _ := toolTestGateway(t, EventAdapter{Repository: NewMemoryEvents(e1, e2)})
	invocation := toolInvocation(e1)
	first := gateway.Invoke(context.Background(), processRequest(nil), invocation)
	if first.Status != StatusOK || len(first.Evidence) != 1 || first.NextCursor == "" {
		t.Fatalf("unexpected first page: %+v", first)
	}
	second := gateway.Invoke(context.Background(), processRequest(first.NextCursor), invocation)
	if second.Status != StatusOK || len(second.Evidence) != 1 || second.NextCursor != "" {
		t.Fatalf("unexpected second page: %+v", second)
	}
	if first.Evidence[0].SourceEventID == second.Evidence[0].SourceEventID {
		t.Fatal("pagination repeated event")
	}
}

func TestGatewayRejectsExtraFieldsBeforeBudget(t *testing.T) {
	event := toolTestEvent("e1", "tenant-1", "host-1", domain.EventProcessExec)
	gateway, _ := toolTestGateway(t, EventAdapter{Repository: NewMemoryEvents(event)})
	invocation := toolInvocation(event)
	budget := invocation.Budget.(*CounterBudget)
	request := processRequest(nil)
	request.Arguments["tenant_id"] = "other"
	result := gateway.Invoke(context.Background(), request, invocation)
	if result.Status != StatusRejected || result.Error.Code != ErrInvalidArguments {
		t.Fatalf("unexpected result: %+v", result)
	}
	if budget.Used != 0 {
		t.Fatal("invalid request consumed external call budget")
	}
}

func TestGatewayRejectsTamperedCursor(t *testing.T) {
	e1 := toolTestEvent("e1", "tenant-1", "host-1", domain.EventProcessExec)
	e2 := toolTestEvent("e2", "tenant-1", "host-1", domain.EventProcessExec)
	gateway, _ := toolTestGateway(t, EventAdapter{Repository: NewMemoryEvents(e1, e2)})
	invocation := toolInvocation(e1)
	first := gateway.Invoke(context.Background(), processRequest(nil), invocation)
	request := processRequest(first.NextCursor + "x")
	result := gateway.Invoke(context.Background(), request, invocation)
	if result.Status != StatusRejected || result.Error.Code != ErrInvalidCursor {
		t.Fatalf("unexpected result: %+v", result)
	}
}

type maliciousAdapter struct{ event domain.Event }

func (m maliciousAdapter) Query(context.Context, Spec, map[string]any, InvocationContext) (AdapterResult, *ToolError) {
	return AdapterResult{Events: []domain.Event{m.event}, Status: StatusOK, Coverage: Coverage{Source: "malicious"}}, nil
}

func TestGatewayRejectsCrossScopeAdapterResult(t *testing.T) {
	inScope := toolTestEvent("e1", "tenant-1", "host-1", domain.EventProcessExec)
	outScope := toolTestEvent("e2", "tenant-2", "host-1", domain.EventProcessExec)
	gateway, _ := toolTestGateway(t, maliciousAdapter{event: outScope})
	result := gateway.Invoke(context.Background(), processRequest(nil), toolInvocation(inScope))
	if result.Error == nil || result.Error.Code != ErrResultScopeViolation {
		t.Fatalf("unexpected result: %+v", result)
	}
}

type failingAuditor struct{}

func (failingAuditor) Write(context.Context, AuditRecord) error { return errors.New("disk failure") }

type countingAdapter struct{ calls int }

func (a *countingAdapter) Query(context.Context, Spec, map[string]any, InvocationContext) (AdapterResult, *ToolError) {
	a.calls++
	return AdapterResult{}, nil
}

func TestAuditFailureStopsBeforeAdapter(t *testing.T) {
	registry, _ := NewRegistry(DefaultSpecs())
	adapter := &countingAdapter{}
	gateway, err := NewGateway(registry, map[string]Adapter{"events": adapter}, []byte("0123456789abcdef0123456789abcdef"), failingAuditor{})
	if err != nil {
		t.Fatal(err)
	}
	event := toolTestEvent("e1", "tenant-1", "host-1", domain.EventProcessExec)
	result := gateway.Invoke(context.Background(), processRequest(nil), toolInvocation(event))
	if result.Error == nil || result.Error.Code != ErrPersistenceFailure {
		t.Fatalf("unexpected result: %+v", result)
	}
	if adapter.calls != 0 {
		t.Fatal("adapter ran without durable TOOL_START audit")
	}
}

func TestEvidenceRedactsSecretsButHashesSource(t *testing.T) {
	event := toolTestEvent("secret-event", "tenant-1", "host-1", domain.EventProcessExec)
	event.Details = json.RawMessage(`{"path":"/tmp/a","authorization":"Bearer secret","nested":{"password":"p"}}`)
	gateway, _ := toolTestGateway(t, EventAdapter{Repository: NewMemoryEvents(event)})
	result := gateway.Invoke(context.Background(), processRequest(nil), toolInvocation(event))
	if len(result.Evidence) != 1 {
		t.Fatalf("expected evidence: %#v", result)
	}
	text := string(result.Evidence[0].Event)
	if strings.Contains(text, "Bearer secret") || strings.Contains(text, `"password":"p"`) || !strings.Contains(text, "[REDACTED]") {
		t.Fatalf("secret redaction failed: %s", text)
	}
}
