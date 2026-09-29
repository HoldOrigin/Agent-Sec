package scenario

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	domain "sentinel/internal/agentdomain"
	investigation "sentinel/internal/agentic"
	llm "sentinel/internal/agentllm"
	tools "sentinel/internal/agenttools"
)

type RunConfig struct {
	Mode          string
	APIKey        string
	PlannerModel  string
	ExecutorModel string
	AnalyzerModel string
	MaxDecisions  int
	MaxToolCalls  int
	TraceWriter   io.Writer
}

type Outcome struct {
	Scenario Scenario                `json:"scenario"`
	Result   investigation.RunResult `json:"result"`
	Passed   bool                    `json:"passed"`
	Failures []string                `json:"failures"`
}

func Run(ctx context.Context, item Scenario, config RunConfig) (Outcome, error) {
	if err := item.Validate(); err != nil {
		return Outcome{}, err
	}
	registry, err := tools.NewRegistry(tools.DefaultSpecs())
	if err != nil {
		return Outcome{}, err
	}
	recorder := NewRecorder(config.TraceWriter)
	repository := tools.NewMemoryEvents(item.Events...)
	eventAdapter := tools.EventAdapter{Repository: repository}
	faults := &faultAdapter{source: item.FailOnceSource, next: eventAdapter}
	adapters := buildAdapters(item, eventAdapter, faults)
	gateway, err := tools.NewGateway(registry, adapters, []byte("agent-sec-scenario-cursor-key-0001"), recorder)
	if err != nil {
		return Outcome{}, err
	}
	roles, err := scenarioRoles(item, config)
	if err != nil {
		return Outcome{}, err
	}
	maxDecisions := config.MaxDecisions
	if maxDecisions <= 0 {
		maxDecisions = 4
	}
	maxCalls := config.MaxToolCalls
	if maxCalls <= 0 {
		maxCalls = 32
	}
	available := map[string]struct{}{}
	for _, call := range item.Calls {
		available[call.Tool] = struct{}{}
	}
	controller := investigation.Controller{Roles: roles, Registry: registry, Gateway: gateway, Logger: recorder, MaxDecisions: maxDecisions, MaxToolCalls: maxCalls}
	result, runErr := controller.Run(ctx, investigation.RunRequest{Alert: item.Alert, Scope: item.Scope, AvailableTools: available, Entities: tools.NewMemoryEntities(item.Entities...)})
	if runErr != nil {
		return Outcome{Scenario: item, Result: result, Passed: false, Failures: []string{runErr.Error()}}, runErr
	}
	outcome := Outcome{Scenario: item, Result: result}
	outcome.Failures = validateOutcome(item, result, recorder.Tools())
	outcome.Passed = len(outcome.Failures) == 0
	return outcome, nil
}

func scenarioRoles(item Scenario, config RunConfig) (investigation.Roles, error) {
	switch config.Mode {
	case "", "deterministic":
		return deterministicRoles(item), nil
	case "qwen":
		caller, err := llm.NewQwen(config.APIKey)
		if err != nil {
			return investigation.Roles{}, err
		}
		retrying := llm.RetryingCaller{Next: caller, MaxAttempts: 3, BaseDelay: 250 * time.Millisecond}
		return investigation.NewQwenRoles(retrying, config.PlannerModel, config.ExecutorModel, config.AnalyzerModel), nil
	default:
		return investigation.Roles{}, fmt.Errorf("unknown mode %q", config.Mode)
	}
}

func buildAdapters(item Scenario, events tools.Adapter, faultyEvents tools.Adapter) map[string]tools.Adapter {
	selectedEvents := events
	if item.FailOnceSource == "events" {
		selectedEvents = faultyEvents
	}
	contextAdapter := tools.EntityContextAdapter{}
	router := func(source string) tools.Adapter {
		event := events
		if item.FailOnceSource == source {
			event = &faultAdapter{source: source, next: events}
		}
		return tools.SourceRouter{Event: event, Context: contextAdapter}
	}
	telemetry := tools.Adapter(scenarioTelemetryAdapter{})
	if item.ID == "degraded-telemetry" {
		telemetry = degradedTelemetryAdapter{}
	}
	return map[string]tools.Adapter{
		"alerts":            tools.AlertAdapter{Repository: memoryAlerts{item.Alert}},
		"telemetry":         telemetry,
		"events":            selectedEvents,
		"auth":              router("auth"),
		"web":               router("web"),
		"kubernetes":        router("kubernetes"),
		"cloud":             router("cloud"),
		"identity":          contextAdapter,
		"network_inventory": contextAdapter,
		"inventory":         contextAdapter,
		"runtime":           contextAdapter,
		"files":             contextAdapter,
		"changes":           contextAdapter,
		"baseline":          contextAdapter,
		"reputation":        contextAdapter,
	}
}

type memoryAlerts struct{ alert domain.Alert }

func (m memoryAlerts) Alert(tenant, id string) (domain.Alert, error) {
	if m.alert.TenantID != tenant || m.alert.ID != id {
		return domain.Alert{}, fmt.Errorf("alert not found")
	}
	return m.alert, nil
}

type scenarioTelemetryAdapter struct{}

func (scenarioTelemetryAdapter) Query(_ context.Context, _ tools.Spec, _ map[string]any, invocation tools.InvocationContext) (tools.AdapterResult, *tools.ToolError) {
	return tools.AdapterResult{Status: tools.StatusOK, Data: map[string]any{"ring_buffer_loss": 0, "upload_policy": "CONFIGURED", "snapshot": invocation.Scope.SnapshotID}, Coverage: tools.Coverage{QueryComplete: true, TelemetryState: "COMPLETE", Source: "scenario-telemetry", CoveredStart: invocation.Scope.Start, CoveredEnd: invocation.Scope.End, Warnings: []string{}}}, nil
}

type degradedTelemetryAdapter struct{}

func (degradedTelemetryAdapter) Query(_ context.Context, _ tools.Spec, _ map[string]any, invocation tools.InvocationContext) (tools.AdapterResult, *tools.ToolError) {
	return tools.AdapterResult{Status: tools.StatusPartial, Data: map[string]any{"ring_buffer_loss": "UNKNOWN", "upload_policy": "CONFIGURED"}, Coverage: tools.Coverage{QueryComplete: false, Truncated: true, TelemetryState: "DEGRADED", Source: "scenario-telemetry", CoveredStart: invocation.Scope.Start, CoveredEnd: invocation.Scope.End, Warnings: []string{"模拟RingBuffer丢失指标不可用"}}}, nil
}

type faultAdapter struct {
	mu     sync.Mutex
	source string
	failed bool
	next   tools.Adapter
}

func (a *faultAdapter) Query(ctx context.Context, spec tools.Spec, args map[string]any, invocation tools.InvocationContext) (tools.AdapterResult, *tools.ToolError) {
	a.mu.Lock()
	if !a.failed {
		a.failed = true
		a.mu.Unlock()
		return tools.AdapterResult{}, &tools.ToolError{Code: tools.ErrSourceUnavailable, SafeMessage: "模拟数据源瞬时不可用", Retryable: true, RetryAfterMS: 1}
	}
	a.mu.Unlock()
	return a.next.Query(ctx, spec, args, invocation)
}

func validateOutcome(item Scenario, result investigation.RunResult, called map[string]int) []string {
	failures := []string{}
	if result.Status != item.Expected.Status {
		failures = append(failures, fmt.Sprintf("status=%s, want %s", result.Status, item.Expected.Status))
	}
	if result.Report.Classification != item.Expected.Classification {
		failures = append(failures, fmt.Sprintf("classification=%s, want %s", result.Report.Classification, item.Expected.Classification))
	}
	for _, tool := range item.Expected.RequiredTools {
		if called[tool] == 0 {
			failures = append(failures, "required tool was not called: "+tool)
		}
	}
	observed := map[string]struct{}{}
	for _, evidence := range result.Evidence {
		observed[evidence.SourceEventID] = struct{}{}
	}
	for _, id := range item.Expected.RequiredEventIDs {
		if _, ok := observed[id]; !ok {
			failures = append(failures, "required event was not collected: "+id)
		}
	}
	return failures
}

type Recorder struct {
	mu     sync.Mutex
	writer io.Writer
	seq    uint64
	tools  map[string]int
}

func NewRecorder(writer io.Writer) *Recorder {
	return &Recorder{writer: writer, tools: map[string]int{}}
}

func (r *Recorder) Log(event string, details map[string]any) error {
	return r.emit("controller", event, map[string]any{"details": details})
}

func (r *Recorder) Write(_ context.Context, record tools.AuditRecord) error {
	var details any
	_ = json.Unmarshal(record.Details, &details)
	if record.Event == "TOOL_START" {
		r.mu.Lock()
		r.tools[record.Tool]++
		r.mu.Unlock()
	}
	return r.emit("tool_gateway", record.Event, map[string]any{"call_id": record.CallID, "tool": record.Tool, "status": record.Status, "details": details})
}

func (r *Recorder) emit(component, event string, fields map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	entry := map[string]any{"sequence": r.seq, "time": time.Now().UTC().Format(time.RFC3339Nano), "component": component, "event": event}
	for key, value := range fields {
		entry[key] = value
	}
	if r.writer == nil {
		return nil
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(r.writer, string(encoded))
	return err
}

func (r *Recorder) Tools() map[string]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make(map[string]int, len(r.tools))
	for name, count := range r.tools {
		result[name] = count
	}
	return result
}

type deterministicPlanner struct{ item Scenario }

func (p deterministicPlanner) Identity() string { return "scenario-planner-v1" }
func (p deterministicPlanner) Plan(context.Context, map[string]any) (investigation.Plan, error) {
	plan := investigation.Plan{Hypotheses: []string{"告警对应真实攻击链", "告警由合法运维或遥测缺失触发"}}
	for _, call := range p.item.Calls {
		plan.Tasks = append(plan.Tasks, investigation.Task{ID: call.ID, Question: call.Question, DependsOn: append([]string(nil), call.DependsOn...), RequiredTools: []string{call.Tool}, OptionalTools: []string{}})
	}
	return plan, nil
}

type deterministicExecutor struct{ calls map[string]Call }

func (e deterministicExecutor) Identity() string { return "scenario-executor-v1" }
func (e deterministicExecutor) NextAction(_ context.Context, input map[string]any) (investigation.Action, error) {
	task, ok := input["task"].(investigation.Task)
	if !ok {
		return investigation.Action{}, fmt.Errorf("task input is missing")
	}
	call, ok := e.calls[task.ID]
	if !ok {
		return investigation.Action{}, fmt.Errorf("no scripted call for %s", task.ID)
	}
	arguments := map[string]any{}
	for key, value := range call.Arguments {
		arguments[key] = value
	}
	return investigation.Action{Action: investigation.ActionCallTool, Purpose: call.Question, Tool: call.Tool, Arguments: arguments}, nil
}

type deterministicAnalyzer struct{ item Scenario }

func (a deterministicAnalyzer) Identity() string { return "scenario-analyzer-v1" }
func (a deterministicAnalyzer) Analyze(_ context.Context, input map[string]any) (investigation.Report, error) {
	evidence, _ := input["evidence"].(map[string]domain.Evidence)
	ids := make([]string, 0, len(evidence))
	for id := range evidence {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	findings := make([]investigation.Finding, 0, len(ids))
	for _, id := range ids {
		findings = append(findings, investigation.Finding{Statement: evidence[id].Fact, Type: "OBSERVED", EvidenceIDs: []string{id}})
	}
	return investigation.Report{Classification: a.item.Expected.AnalyzerClassification, Summary: "场景驱动器完成受控调查：" + a.item.Name, Findings: findings, MissingEvidence: append([]string(nil), a.item.Expected.MissingEvidence...), Recommendations: []string{"仅在隔离测试环境复核原始事件"}}, nil
}

func deterministicRoles(item Scenario) investigation.Roles {
	calls := map[string]Call{}
	for _, call := range item.Calls {
		calls[call.ID] = call
	}
	return investigation.Roles{Planner: deterministicPlanner{item}, Executor: deterministicExecutor{calls}, Analyzer: deterministicAnalyzer{item}}
}
