package investigation

import (
	"context"
	"fmt"

	"sentinel/internal/agentllm"
)

type Planner interface {
	Identity() string
	Plan(context.Context, map[string]any) (Plan, error)
}
type Executor interface {
	Identity() string
	NextAction(context.Context, map[string]any) (Action, error)
}
type Analyzer interface {
	Identity() string
	Analyze(context.Context, map[string]any) (Report, error)
}

type Roles struct {
	Planner  Planner
	Executor Executor
	Analyzer Analyzer
}

func (r Roles) Validate() error {
	if r.Planner == nil || r.Executor == nil || r.Analyzer == nil {
		return fmt.Errorf("planner, executor and analyzer are required")
	}
	return nil
}
func (r Roles) Identities() map[string]string {
	return map[string]string{"planner": r.Planner.Identity(), "executor": r.Executor.Identity(), "analyzer": r.Analyzer.Identity()}
}

type QwenPlanner struct {
	caller llm.Caller
	model  string
}
type QwenExecutor struct {
	caller llm.Caller
	model  string
}
type QwenAnalyzer struct {
	caller llm.Caller
	model  string
}

func NewQwenRoles(caller llm.Caller, plannerModel, executorModel, analyzerModel string) Roles {
	if plannerModel == "" {
		plannerModel = llm.DefaultModel
	}
	if executorModel == "" {
		executorModel = llm.DefaultModel
	}
	if analyzerModel == "" {
		analyzerModel = llm.DefaultModel
	}
	return Roles{Planner: &QwenPlanner{caller, plannerModel}, Executor: &QwenExecutor{caller, executorModel}, Analyzer: &QwenAnalyzer{caller, analyzerModel}}
}
func (q *QwenPlanner) Identity() string  { return q.model }
func (q *QwenExecutor) Identity() string { return q.model }
func (q *QwenAnalyzer) Identity() string { return q.model }

func (q *QwenPlanner) Plan(ctx context.Context, input map[string]any) (Plan, error) {
	contract := map[string]any{"exact_shape": map[string]any{"hypotheses": []string{"字符串"}, "tasks": []map[string]any{{"task_id": "T1", "question": "字符串", "depends_on": []string{}, "required_tools": []string{"available_tools中的名称"}, "optional_tools": []string{}}}},
		"rules": []string{"只能输出exact_shape中的字段", "task_id必须是T1至T99格式", "安排1至8个任务", "每个任务至少一个required_tools", "工具必须来自available_tools", "依赖不得成环", "正常解释和攻击解释都应考虑"}}
	var output Plan
	err := q.caller.Call(ctx, q.model, "PLAN", "你的唯一职责是生成调查计划，不得假装工具已执行。", contract, input, &output)
	return output, err
}
func (q *QwenExecutor) NextAction(ctx context.Context, input map[string]any) (Action, error) {
	contract := map[string]any{"choose_exactly_one_shape": []map[string]any{
		{"action": "CALL_TOOL", "purpose": "字符串", "tool": "active_tools中的名称", "arguments": "严格按该工具input_schema生成的对象"},
		{"action": "FINISH", "findings": []map[string]any{{"statement": "字符串", "type": "OBSERVED|INFERRED|UNKNOWN", "evidence_ids": []string{"ev-id"}}}, "gaps": []string{}},
		{"action": "REQUEST_REPLAN", "reason": "字符串", "evidence_refs": []string{"ev-id"}}},
		"rules": []string{"只能输出所选shape中的字段，不得输出thought、analysis、reasoning、checks或null占位字段", "每轮只选择一个动作", "CALL_TOOL只能使用active_tools并逐项满足input_schema的类型、枚举、minimum、maximum及scope_root_constraint", "entity_ref应优先从registered_entities选择类型匹配的真实ID；若使用scope则relation必须为tree", "上一次观察为REJECTED时必须依据error字段修改参数，禁止原样重复", "OBSERVED的statement必须完全复制一条提供的证据fact且只引用其ID", "不得扩大Scope"}}
	var output Action
	err := q.caller.Call(ctx, q.model, "REACT", "你的唯一职责是选择当前任务的下一动作，不得直接执行工具。", contract, input, &output)
	return output, err
}
func (q *QwenAnalyzer) Analyze(ctx context.Context, input map[string]any) (Report, error) {
	contract := map[string]any{"exact_shape": map[string]any{"classification": "SUSPICIOUS|NO_ATTACK_EVIDENCE|INCONCLUSIVE", "summary": "字符串", "findings": []map[string]any{{"statement": "字符串", "type": "OBSERVED|INFERRED|UNKNOWN", "evidence_ids": []string{"ev-id"}}}, "missing_evidence": []string{}, "recommendations": []string{}},
		"rules": []string{"只能输出exact_shape中的字段", "只能引用已登记证据", "OBSERVED的statement必须完全复制证据fact", "空结果不证明安全", "明确区分事实、推断和未知"}}
	var output Report
	err := q.caller.Call(ctx, q.model, "ANALYZE", "你的唯一职责是汇总任务和证据，不得调用工具。", contract, input, &output)
	return output, err
}
