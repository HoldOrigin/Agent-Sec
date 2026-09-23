package investigation

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"sentinel/internal/agentdomain"
	"sentinel/internal/agenttools"
)

type fixedPlanner struct{ plan Plan }

func (p fixedPlanner) Identity() string                                   { return "planner-test" }
func (p fixedPlanner) Plan(context.Context, map[string]any) (Plan, error) { return p.plan, nil }

type scriptedExecutor struct{ calls int }

func (e *scriptedExecutor) Identity() string { return "executor-test" }
func (e *scriptedExecutor) NextAction(_ context.Context, input map[string]any) (Action, error) {
	e.calls++
	if e.calls == 1 {
		return Action{Action: ActionCallTool, Purpose: "查询种子进程", Tool: "process_events_query", Arguments: map[string]any{
			"entity_ref": "process-1", "relation": "self", "event_types": []any{"PROCESS_EXEC"}, "limit": json.Number("50"), "cursor": nil}}, nil
	}
	evidence := input["evidence"].(map[string]domain.Evidence)
	for id, item := range evidence {
		return Action{Action: ActionFinish, Findings: []Finding{{Statement: item.Fact, Type: "OBSERVED", EvidenceIDs: []string{id}}}}, nil
	}
	return Action{Action: ActionFinish}, nil
}

type evidenceAnalyzer struct{}

func (evidenceAnalyzer) Identity() string { return "analyzer-test" }
func (evidenceAnalyzer) Analyze(_ context.Context, input map[string]any) (Report, error) {
	evidence := input["evidence"].(map[string]domain.Evidence)
	for id, item := range evidence {
		return Report{Classification: "SUSPICIOUS", Summary: "发现已验证执行事件", Findings: []Finding{{Statement: item.Fact, Type: "OBSERVED", EvidenceIDs: []string{id}}}, MissingEvidence: []string{}, Recommendations: []string{"人工复核"}}, nil
	}
	return Report{Classification: "INCONCLUSIVE"}, nil
}

type recordingLogger struct{ events []string }

func (l *recordingLogger) Log(event string, _ map[string]any) error {
	l.events = append(l.events, event)
	return nil
}

func TestControllerPlanExecuteAndAnalyze(t *testing.T) {
	now := time.Now().UTC()
	event := domain.Event{ID: "event-1", SchemaVersion: 1, TenantID: "tenant-1", SensorID: "sensor-1", HostID: "host-1", BootID: "boot-1",
		ProcessID: "process-1", Kind: domain.EventProcessExec, Outcome: domain.OutcomeSuccess, ObservedAt: now, IngestedAt: now, Details: json.RawMessage(`{"path":"/bin/sh"}`)}
	repository := tools.NewMemoryEvents(event)
	registry, err := tools.NewRegistry(tools.DefaultSpecs())
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := tools.NewGateway(registry, map[string]tools.Adapter{"events": tools.EventAdapter{Repository: repository}}, []byte("01234567890123456789012345678901"), nil)
	if err != nil {
		t.Fatal(err)
	}
	executor := &scriptedExecutor{}
	logger := &recordingLogger{}
	controller := Controller{Roles: Roles{Planner: fixedPlanner{Plan{Hypotheses: []string{"攻击", "正常操作"}, Tasks: []Task{{ID: "T1", Question: "发生了什么进程执行？", RequiredTools: []string{"process_events_query"}, OptionalTools: []string{}}}}}, Executor: executor, Analyzer: evidenceAnalyzer{}},
		Registry: registry, Gateway: gateway, Logger: logger, MaxDecisions: 3, MaxToolCalls: 3}
	scope := domain.Scope{ID: "scope-1", TenantID: "tenant-1", Start: now.Add(-time.Minute), End: now.Add(time.Minute), AllowedHosts: []string{"host-1"}, SnapshotID: "snapshot-1"}
	entities := tools.NewMemoryEntities(domain.Entity{ID: "process-1", Type: domain.EntityProcess, TenantID: scope.TenantID, ScopeID: scope.ID, SnapshotID: scope.SnapshotID})
	result, err := controller.Run(context.Background(), RunRequest{Alert: domain.Alert{ID: "alert-1", TenantID: "tenant-1", SeedEventID: event.ID, CreatedAt: now}, Scope: scope,
		AvailableTools: map[string]struct{}{"process_events_query": {}}, Entities: entities})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "COMPLETED" || result.Report.Classification != "SUSPICIOUS" || len(result.Evidence) != 1 {
		t.Fatalf("unexpected result: %#v", result)
	}
	if len(logger.events) < 7 || logger.events[0] != "RUN_START" || logger.events[len(logger.events)-1] != "RUN_END" {
		t.Fatalf("incomplete audit events: %#v", logger.events)
	}
}

func TestReportRejectsUnreferencedObservedClaim(t *testing.T) {
	err := validateReport(Report{Classification: "SUSPICIOUS", Findings: []Finding{{Statement: "没有证据的事实", Type: "OBSERVED"}}}, map[string]domain.Evidence{})
	if err == nil {
		t.Fatal("unreferenced observed claim was accepted")
	}
}

func TestSafeRequiredActionUsesBoundedScopeQuery(t *testing.T) {
	registry, err := tools.NewRegistry(tools.DefaultSpecs())
	if err != nil {
		t.Fatal(err)
	}
	action, ok := safeRequiredAction(Task{RequiredTools: []string{"process_events_query"}}, registry, tools.NewMemoryEntities(), domain.Scope{ID: "scope-1"}, map[string]struct{}{})
	if !ok || action.Tool != "process_events_query" || action.Arguments["entity_ref"] != "scope" || action.Arguments["relation"] != "tree" || action.Arguments["limit"] != int64(50) {
		t.Fatalf("unexpected repaired action: %#v", action)
	}
}
