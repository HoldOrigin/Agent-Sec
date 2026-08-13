package security.agent

default decision := {"decision": "deny", "allow": false, "approval": false, "reason": "动作不在 MVP 白名单中"}

readonly_actions := {
  "query_runtime_events",
  "query_network_events",
  "query_file_events",
  "query_vulnerability",
  "query_historical_baseline",
  "get_process_tree",
  "get_container_context",
  "generate_report",
  "create_ticket",
}

approval_actions := {"block_ip", "isolate_pod", "quarantine_file"}
denied_actions := {"delete_pod", "revoke_credential"}

decision := {"decision": "allow", "allow": true, "approval": false, "reason": "只读调查或报告动作自动允许"} if {
  input.action in readonly_actions
}

decision := {"decision": "require_approval", "allow": false, "approval": true, "reason": reason} if {
  input.action in approval_actions
  reason := object.get({
    true: "生产环境写操作必须人工审批",
    false: "高风险处置动作必须人工审批",
  }, input.target.namespace == "production", "高风险处置动作必须人工审批")
}

decision := {"decision": "deny", "allow": false, "approval": false, "reason": "破坏性动作在 MVP 中默认禁止"} if {
  input.action in denied_actions
}
