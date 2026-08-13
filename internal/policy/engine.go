package policy

import (
	"sentinel/internal/model"
	"time"
)

type ActionRequest struct {
	Actor      string         `json:"actor"`
	Action     string         `json:"action"`
	Target     map[string]any `json:"target"`
	Risk       string         `json:"risk"`
	IncidentID string         `json:"incident_id"`
}
type Engine struct{}

func New() *Engine { return &Engine{} }
func (e *Engine) Evaluate(request ActionRequest) model.PolicyDecision {
	readonly := set("query_runtime_events", "query_network_events", "query_file_events", "query_vulnerability", "query_historical_baseline", "get_process_tree", "get_container_context", "generate_report", "create_ticket")
	approval := set("block_ip", "isolate_pod", "quarantine_file")
	denied := set("delete_pod", "revoke_credential")
	decision := "deny"
	reason := "动作不在 MVP 白名单中"
	if readonly[request.Action] {
		decision = "allow"
		reason = "只读调查或报告动作自动允许"
	} else if denied[request.Action] {
		reason = "破坏性动作在 MVP 中默认禁止"
	} else if approval[request.Action] {
		decision = "require_approval"
		reason = "高风险处置动作必须人工审批"
		if namespace, ok := request.Target["namespace"].(string); ok && namespace == "production" {
			reason = "生产环境写操作必须人工审批"
		}
	}
	return model.PolicyDecision{Decision: decision, Allow: decision == "allow", Approval: decision == "require_approval", Reason: reason, PolicyVersion: "mvp-v1", EvaluatedAt: time.Now().UTC()}
}
func set(values ...string) map[string]bool {
	r := map[string]bool{}
	for _, v := range values {
		r[v] = true
	}
	return r
}
