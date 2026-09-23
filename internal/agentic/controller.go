package investigation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"sentinel/internal/agentdomain"
	"sentinel/internal/agenttools"
)

type RunRequest struct {
	Alert          domain.Alert
	Scope          domain.Scope
	AvailableTools map[string]struct{}
	Entities       tools.EntityResolver
}

type RunResult struct {
	RunID      string                     `json:"run_id"`
	Status     string                     `json:"status"`
	Models     map[string]string          `json:"models"`
	Plan       Plan                       `json:"plan"`
	Tasks      map[string]TaskResult      `json:"tasks"`
	Evidence   map[string]domain.Evidence `json:"evidence"`
	Report     Report                     `json:"report"`
	StartedAt  time.Time                  `json:"started_at"`
	FinishedAt time.Time                  `json:"finished_at"`
}

type EventLogger interface {
	Log(event string, details map[string]any) error
}
type NopLogger struct{}

func (NopLogger) Log(string, map[string]any) error { return nil }

type Controller struct {
	Roles        Roles
	Registry     *tools.Registry
	Gateway      *tools.Gateway
	Logger       EventLogger
	MaxDecisions int
	MaxToolCalls int
}

func (c *Controller) Run(ctx context.Context, request RunRequest) (RunResult, error) {
	if err := c.Roles.Validate(); err != nil {
		return RunResult{}, err
	}
	if c.Registry == nil || c.Gateway == nil {
		return RunResult{}, fmt.Errorf("registry and gateway are required")
	}
	if c.Logger == nil {
		c.Logger = NopLogger{}
	}
	if c.MaxDecisions <= 0 {
		c.MaxDecisions = 4
	}
	if c.MaxToolCalls <= 0 {
		c.MaxToolCalls = 12
	}
	if request.Alert.ID == "" || request.Alert.TenantID != request.Scope.TenantID || request.Entities == nil || len(request.AvailableTools) == 0 {
		return RunResult{}, fmt.Errorf("invalid investigation request")
	}
	result := RunResult{RunID: newID("run-"), Status: "RUNNING", Models: c.Roles.Identities(), Tasks: map[string]TaskResult{}, Evidence: map[string]domain.Evidence{}, StartedAt: time.Now().UTC()}
	if err := c.log("RUN_START", map[string]any{"run_id": result.RunID, "alert_id": request.Alert.ID, "models": result.Models}); err != nil {
		return RunResult{}, err
	}
	planInput := map[string]any{"alert": request.Alert, "scope": request.Scope, "available_tools": c.Registry.PublicCatalog(request.AvailableTools)}
	plan, err := c.Roles.Planner.Plan(ctx, planInput)
	if err != nil {
		return c.fail(result, "PLANNER_ERROR", err)
	}
	if err := ValidatePlan(plan, request.AvailableTools); err != nil {
		if logErr := c.log("PLAN_REJECTED", map[string]any{"run_id": result.RunID, "reason": err.Error()}); logErr != nil {
			return RunResult{}, logErr
		}
		plan = fallbackPlan(request.AvailableTools)
		if fallbackErr := ValidatePlan(plan, request.AvailableTools); fallbackErr != nil {
			return c.fail(result, "INVALID_PLAN", fallbackErr)
		}
		if logErr := c.log("PLAN_FALLBACK", map[string]any{"run_id": result.RunID, "plan": plan}); logErr != nil {
			return RunResult{}, logErr
		}
	}
	result.Plan = plan
	if err := c.log("PLAN_ACCEPTED", map[string]any{"run_id": result.RunID, "plan": plan}); err != nil {
		return RunResult{}, err
	}
	budget := &tools.CounterBudget{Limit: c.MaxToolCalls}
	for len(result.Tasks) < len(plan.Tasks) {
		progress := false
		for _, task := range plan.Tasks {
			if _, done := result.Tasks[task.ID]; done {
				continue
			}
			dependenciesReady, dependencyFailed := true, false
			for _, dependency := range task.DependsOn {
				dependency, exists := result.Tasks[dependency]
				if !exists {
					dependenciesReady = false
					break
				}
				if dependency.Status != "SUCCEEDED" {
					dependencyFailed = true
				}
			}
			if !dependenciesReady {
				continue
			}
			progress = true
			if dependencyFailed {
				result.Tasks[task.ID] = TaskResult{TaskID: task.ID, Status: "BLOCKED", Findings: []Finding{}, Gaps: []string{"DEPENDENCY_INCOMPLETE"}, Observations: []map[string]any{}, EvidenceRefs: []string{}}
				continue
			}
			result.Tasks[task.ID] = c.executeTask(ctx, result.RunID, task, request, budget, result.Evidence)
		}
		if !progress {
			return c.fail(result, "SCHEDULER_STALLED", fmt.Errorf("task graph did not progress"))
		}
	}
	report, err := c.Roles.Analyzer.Analyze(ctx, map[string]any{"alert": request.Alert, "scope": request.Scope, "tasks": result.Tasks, "evidence": result.Evidence})
	if err != nil || validateReport(report, result.Evidence) != nil {
		report = fallbackReport(result.Evidence, "模型汇总失败或报告校验未通过")
	}
	result.Report = report
	result.Status = "COMPLETED"
	for _, task := range result.Tasks {
		if task.Status != "SUCCEEDED" || len(task.Gaps) > 0 {
			result.Status = "NEEDS_REVIEW"
		}
	}
	if report.Classification == "NO_ATTACK_EVIDENCE" {
		result.Report.Classification = "INCONCLUSIVE"
		result.Status = "NEEDS_REVIEW"
	}
	result.FinishedAt = time.Now().UTC()
	if err := c.log("RUN_END", map[string]any{"run_id": result.RunID, "status": result.Status, "classification": result.Report.Classification}); err != nil {
		return RunResult{}, err
	}
	return result, nil
}

func fallbackPlan(available map[string]struct{}) Plan {
	plan := Plan{Hypotheses: []string{"异常命令执行形成了文件落地、外联或权限变更攻击链", "经授权的运维或应用行为触发了检测规则"}, Tasks: []Task{}}
	add := func(id, question, tool string, dependencies ...string) {
		if _, ok := available[tool]; !ok {
			return
		}
		plan.Tasks = append(plan.Tasks, Task{ID: id, Question: question, DependsOn: dependencies, RequiredTools: []string{tool}, OptionalTools: []string{}})
	}
	add("T1", "确认种子进程及其父子执行关系和结果", "process_events_query")
	dependencies := []string{}
	if len(plan.Tasks) > 0 {
		dependencies = []string{"T1"}
	}
	add("T2", "检查关联进程的文件创建和修改", "file_events_query", dependencies...)
	add("T3", "检查关联进程的网络连接", "network_connections_query", dependencies...)
	add("T4", "检查命名空间、挂载和跨进程等内核高危行为", "kernel_security_events_query", dependencies...)
	if len(plan.Tasks) == 0 {
		for tool := range available {
			plan.Tasks = append(plan.Tasks, Task{ID: "T1", Question: "查询当前告警可用事实", RequiredTools: []string{tool}, OptionalTools: []string{}})
			break
		}
	}
	return plan
}

func (c *Controller) executeTask(ctx context.Context, runID string, task Task, request RunRequest, budget *tools.CounterBudget, evidence map[string]domain.Evidence) TaskResult {
	result := TaskResult{TaskID: task.ID, Status: "PARTIAL", Findings: []Finding{}, Gaps: []string{}, Observations: []map[string]any{}, EvidenceRefs: []string{}}
	if err := c.log("TASK_START", map[string]any{"run_id": runID, "task_id": task.ID, "question": task.Question, "required_tools": task.RequiredTools}); err != nil {
		result.Gaps = append(result.Gaps, "AUDIT_FAILURE")
		return result
	}
	allowed := map[string]struct{}{}
	for _, name := range append(append([]string(nil), task.RequiredTools...), task.OptionalTools...) {
		allowed[name] = struct{}{}
	}
	completed := map[string]struct{}{}
	for step := 1; step <= c.MaxDecisions; step++ {
		active := map[string]struct{}{}
		for name := range allowed {
			if _, runAllowed := request.AvailableTools[name]; runAllowed {
				active[name] = struct{}{}
			}
		}
		action, err := c.Roles.Executor.NextAction(ctx, map[string]any{"task": task, "step": step,
			"active_tools": c.Registry.PublicCatalog(active), "observations": result.Observations,
			"alert": request.Alert, "scope": request.Scope, "registered_entities": visibleEntities(request.Entities),
			"evidence": visibleAllEvidence(evidence), "remaining_decisions": c.MaxDecisions - step + 1})
		if err != nil {
			_ = c.log("ACTION_FAILED", map[string]any{"run_id": runID, "task_id": task.ID, "step": step, "error_type": fmt.Sprintf("%T", err), "error": err.Error()})
			result.Gaps = append(result.Gaps, "EXECUTOR_ERROR")
			break
		}
		_ = c.log("ACTION_SELECTED", map[string]any{"run_id": runID, "task_id": task.ID, "step": step, "action": action})
		if err := ValidateAction(action, task, active); err != nil {
			repaired, ok := safeRequiredAction(task, c.Registry, request.Entities, request.Scope, completed)
			if !ok {
				result.Observations = append(result.Observations, map[string]any{"status": "INVALID_ACTION", "error": err.Error()})
				continue
			}
			action = repaired
			_ = c.log("ACTION_REPAIRED", map[string]any{"run_id": runID, "task_id": task.ID, "step": step, "reason": err.Error(), "action": action})
		}
		switch action.Action {
		case ActionCallTool:
			if _, alreadyComplete := completed[action.Tool]; alreadyComplete {
				if repaired, ok := safeRequiredAction(task, c.Registry, request.Entities, request.Scope, completed); ok {
					action = repaired
					_ = c.log("ACTION_REPAIRED", map[string]any{"run_id": runID, "task_id": task.ID, "step": step, "reason": "NO_PROGRESS_REPEAT", "action": action})
				}
			}
			toolResult := c.Gateway.Invoke(ctx, tools.Request{CallID: newID("call-"), Tool: action.Tool, Arguments: action.Arguments}, tools.InvocationContext{
				RunID: runID, TaskID: task.ID, Scope: request.Scope, AllowedTools: allowed, ActiveTools: active, Entities: request.Entities, Budget: budget})
			if toolResult.Error != nil && toolResult.Error.Retryable && toolResult.Error.Code == tools.ErrSourceUnavailable {
				toolResult = c.Gateway.Invoke(ctx, tools.Request{CallID: newID("call-"), Tool: action.Tool, Arguments: action.Arguments}, tools.InvocationContext{
					RunID: runID, TaskID: task.ID, Scope: request.Scope, AllowedTools: allowed, ActiveTools: active, Entities: request.Entities, Budget: budget})
			}
			if toolResult.Error != nil && repairableArgumentError(toolResult.Error.Code) {
				if repaired, ok := safeRequiredAction(task, c.Registry, request.Entities, request.Scope, completed); ok && hashAction(repaired) != hashAction(action) {
					action = repaired
					_ = c.log("ACTION_REPAIRED", map[string]any{"run_id": runID, "task_id": task.ID, "step": step, "reason": toolResult.Error.Code, "action": action})
					toolResult = c.Gateway.Invoke(ctx, tools.Request{CallID: newID("call-"), Tool: action.Tool, Arguments: action.Arguments}, tools.InvocationContext{
						RunID: runID, TaskID: task.ID, Scope: request.Scope, AllowedTools: allowed, ActiveTools: active, Entities: request.Entities, Budget: budget})
				}
			}
			encoded, _ := json.Marshal(toolResult)
			var observation map[string]any
			_ = json.Unmarshal(encoded, &observation)
			result.Observations = append(result.Observations, observation)
			_ = c.log("TOOL_OBSERVATION", map[string]any{"run_id": runID, "task_id": task.ID, "step": step, "request": map[string]any{"tool": action.Tool, "arguments": action.Arguments}, "result": toolResult})
			for _, item := range toolResult.Evidence {
				evidence[item.ID] = item
				result.EvidenceRefs = appendUnique(result.EvidenceRefs, item.ID)
			}
			if (toolResult.Status == tools.StatusOK || toolResult.Status == tools.StatusEmpty) && toolResult.Coverage.QueryComplete {
				completed[action.Tool] = struct{}{}
			}
			if len(task.OptionalTools) == 0 && requiredComplete(task.RequiredTools, completed) {
				result.Status = "SUCCEEDED"
				for _, id := range result.EvidenceRefs {
					if item, ok := evidence[id]; ok {
						result.Findings = append(result.Findings, Finding{Statement: item.Fact, Type: "OBSERVED", EvidenceIDs: []string{id}})
					}
				}
				_ = c.log("TASK_END", map[string]any{"run_id": runID, "task_id": task.ID, "status": result.Status, "findings": result.Findings, "gaps": result.Gaps, "completion": "REQUIRED_QUERIES_COMPLETE"})
				return result
			}
		case ActionFinish:
			if !requiredComplete(task.RequiredTools, completed) {
				result.Observations = append(result.Observations, map[string]any{"status": "FINISH_REJECTED", "error": "required tools are incomplete"})
				continue
			}
			if err := validateFindings(action.Findings, evidence); err != nil {
				result.Observations = append(result.Observations, map[string]any{"status": "FINISH_REJECTED", "error": err.Error()})
				continue
			}
			result.Status = "SUCCEEDED"
			result.Findings = action.Findings
			result.Gaps = append(result.Gaps, action.Gaps...)
			_ = c.log("TASK_END", map[string]any{"run_id": runID, "task_id": task.ID, "status": result.Status, "findings": result.Findings, "gaps": result.Gaps})
			return result
		case ActionRequestReplan:
			result.Gaps = append(result.Gaps, "REPLAN_REQUESTED:"+action.Reason)
			return result
		}
	}
	result.Gaps = appendUnique(result.Gaps, "STEP_LIMIT_OR_EXECUTION_FAILURE")
	_ = c.log("TASK_END", map[string]any{"run_id": runID, "task_id": task.ID, "status": result.Status, "findings": result.Findings, "gaps": result.Gaps})
	return result
}

func repairableArgumentError(code tools.ErrorCode) bool {
	return code == tools.ErrInvalidArguments || code == tools.ErrUnknownEntity || code == tools.ErrEntityTypeMismatch || code == tools.ErrRelationNotAllowed
}

func hashAction(action Action) string {
	encoded, _ := json.Marshal(action)
	return string(encoded)
}

func safeRequiredAction(task Task, registry *tools.Registry, resolver tools.EntityResolver, scope domain.Scope, completed map[string]struct{}) (Action, bool) {
	name := ""
	for _, candidate := range task.RequiredTools {
		if _, done := completed[candidate]; !done {
			name = candidate
			break
		}
	}
	if name == "" {
		return Action{}, false
	}
	spec, ok := registry.Get(name)
	if !ok {
		return Action{}, false
	}
	args := map[string]any{}
	var entities []domain.Entity
	if lister, ok := resolver.(interface{ List() []domain.Entity }); ok {
		entities = lister.List()
	}
	for fieldName, field := range spec.Fields {
		if field.Nullable {
			args[fieldName] = nil
			continue
		}
		switch field.Kind {
		case tools.FieldInteger:
			value := field.MaxInt
			if value == 0 {
				value = field.MinInt
			}
			args[fieldName] = value
		case tools.FieldStringArray:
			if len(field.Enum) == 0 {
				return Action{}, false
			}
			values := append([]string(nil), field.Enum...)
			if field.MaxLength > 0 && len(values) > field.MaxLength {
				values = values[:field.MaxLength]
			}
			args[fieldName] = values
		case tools.FieldString:
			if fieldName == "entity_ref" && spec.AllowScopeRoot {
				args[fieldName] = "scope"
				continue
			}
			if fieldName == "relation" {
				if spec.AllowScopeRoot {
					args[fieldName] = "tree"
				} else if len(field.Enum) > 0 {
					args[fieldName] = field.Enum[0]
				} else {
					return Action{}, false
				}
				continue
			}
			if len(field.EntityTypes) > 0 {
				found := false
				for _, entity := range entities {
					for _, entityType := range field.EntityTypes {
						if entity.Type == entityType {
							args[fieldName] = entity.ID
							found = true
							break
						}
					}
					if found {
						break
					}
				}
				if !found {
					return Action{}, false
				}
			} else if fieldName == "scope_ref" {
				args[fieldName] = scope.ID
			} else if len(field.Enum) > 0 {
				args[fieldName] = field.Enum[0]
			} else {
				return Action{}, false
			}
		}
	}
	return Action{Action: ActionCallTool, Purpose: "模型参数未通过校验，Controller使用工具契约生成最小安全查询", Tool: name, Arguments: args}, true
}

func validateFindings(findings []Finding, evidence map[string]domain.Evidence) error {
	for _, finding := range findings {
		if finding.Type != "OBSERVED" && finding.Type != "INFERRED" && finding.Type != "UNKNOWN" {
			return fmt.Errorf("invalid finding type")
		}
		if finding.Type != "UNKNOWN" && len(finding.EvidenceIDs) == 0 {
			return fmt.Errorf("non-UNKNOWN finding requires evidence")
		}
		for _, id := range finding.EvidenceIDs {
			item, ok := evidence[id]
			if !ok {
				return fmt.Errorf("unknown evidence %s", id)
			}
			if finding.Type == "OBSERVED" && (len(finding.EvidenceIDs) != 1 || finding.Statement != item.Fact) {
				return fmt.Errorf("OBSERVED must copy one evidence fact")
			}
		}
	}
	return nil
}
func validateReport(report Report, evidence map[string]domain.Evidence) error {
	if report.Classification != "SUSPICIOUS" && report.Classification != "NO_ATTACK_EVIDENCE" && report.Classification != "INCONCLUSIVE" {
		return fmt.Errorf("invalid classification")
	}
	return validateFindings(report.Findings, evidence)
}
func fallbackReport(evidence map[string]domain.Evidence, gap string) Report {
	ids := make([]string, 0, len(evidence))
	for id := range evidence {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	findings := []Finding{}
	for _, id := range ids {
		findings = append(findings, Finding{Statement: evidence[id].Fact, Type: "OBSERVED", EvidenceIDs: []string{id}})
	}
	return Report{Classification: "INCONCLUSIVE", Summary: "仅输出已验证事实，无法完成模型汇总", Findings: findings, MissingEvidence: []string{gap}, Recommendations: []string{"人工核对原始事件和缺失上下文"}}
}
func visibleEvidence(ids []string, all map[string]domain.Evidence) map[string]domain.Evidence {
	out := map[string]domain.Evidence{}
	for _, id := range ids {
		if item, ok := all[id]; ok {
			out[id] = item
		}
	}
	return out
}

func visibleAllEvidence(all map[string]domain.Evidence) map[string]domain.Evidence {
	ids := make([]string, 0, len(all))
	for id := range all {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) > 100 {
		ids = ids[len(ids)-100:]
	}
	return visibleEvidence(ids, all)
}

func visibleEntities(resolver tools.EntityResolver) []map[string]string {
	lister, ok := resolver.(interface{ List() []domain.Entity })
	if !ok {
		return []map[string]string{}
	}
	entities := lister.List()
	if len(entities) > 100 {
		entities = entities[:100]
	}
	result := make([]map[string]string, 0, len(entities))
	for _, entity := range entities {
		result = append(result, map[string]string{"id": entity.ID, "type": string(entity.Type)})
	}
	return result
}
func requiredComplete(required []string, completed map[string]struct{}) bool {
	for _, name := range required {
		if _, ok := completed[name]; !ok {
			return false
		}
	}
	return true
}
func appendUnique(values []string, additions ...string) []string {
	seen := map[string]struct{}{}
	for _, value := range values {
		seen[value] = struct{}{}
	}
	for _, value := range additions {
		if _, ok := seen[value]; !ok {
			values = append(values, value)
			seen[value] = struct{}{}
		}
	}
	return values
}
func newID(prefix string) string {
	value := make([]byte, 12)
	_, _ = rand.Read(value)
	return prefix + hex.EncodeToString(value)
}
func (c *Controller) log(event string, details map[string]any) error {
	return c.Logger.Log(event, details)
}
func (c *Controller) fail(result RunResult, code string, err error) (RunResult, error) {
	result.Status = "FAILED"
	result.FinishedAt = time.Now().UTC()
	_ = c.log("RUN_FAILED", map[string]any{"run_id": result.RunID, "code": code, "error_type": fmt.Sprintf("%T", err), "error": err.Error()})
	return result, fmt.Errorf("%s: %w", code, err)
}
