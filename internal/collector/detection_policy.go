package collector

import "path/filepath"

type DetectionDecision struct {
	Alert     bool
	Blacklist bool
	Whitelist bool
	RuleID    string
	Severity  string
	Reason    string
}

type DetectionPolicy interface {
	Evaluate(event map[string]any) DetectionDecision
}

// DefaultDetectionPolicy is a deliberately small local safety net and the
// fallback beneath the compiled CEL blacklist/whitelist snapshot.
type DefaultDetectionPolicy struct{}

func NewDefaultDetectionPolicy() *DefaultDetectionPolicy { return &DefaultDetectionPolicy{} }

func (*DefaultDetectionPolicy) Evaluate(event map[string]any) DetectionDecision {
	metadata := eventMap(event, "metadata")
	if valueBool(metadata["blacklist_hit"]) || valueBool(metadata["security_alert"]) {
		return DetectionDecision{Alert: true, Blacklist: valueBool(metadata["blacklist_hit"]), RuleID: firstString(valueString(metadata["detection_rule_id"]), "LOCAL-BLACKLIST"), Severity: firstString(valueString(metadata["detection_severity"]), "critical"), Reason: firstString(valueString(metadata["detection_reason"]), "external security rule")}
	}
	// A whitelist suppresses built-in heuristics but never overrides an explicit
	// blacklist/security-alert decision above.
	if valueBool(metadata["whitelist_hit"]) {
		return DetectionDecision{}
	}
	eventType := eventString(event, "event_type")
	if alwaysEventType(eventType) {
		return DetectionDecision{Alert: true, RuleID: "LOCAL-CRITICAL-STATE", Severity: "high", Reason: "critical state change"}
	}
	if eventType == "process_exec" {
		executable := firstString(valueString(eventMap(event, "process")["exe"]), valueString(metadata["exec_path"]))
		if isTempRuntimePath(executable) {
			return DetectionDecision{Alert: true, RuleID: "LOCAL-TEMP-EXEC", Severity: "critical", Reason: "temporary path execution"}
		}
		parent := filepath.Base(eventString(event, "parent_process"))
		if isWebProcess(parent) && isShell(filepath.Base(executable)) {
			return DetectionDecision{Alert: true, RuleID: "LOCAL-WEB-SHELL", Severity: "critical", Reason: "web process spawned shell"}
		}
	}
	path := valueString(metadata["path"])
	if eventType == "file_chmod" && valueBool(metadata["executable"]) && isTempRuntimePath(path) {
		return DetectionDecision{Alert: true, RuleID: "LOCAL-TEMP-CHMOD", Severity: "high", Reason: "temporary file made executable"}
	}
	if isFileMutation(eventType) && isSensitiveRuntimePath(path) {
		return DetectionDecision{Alert: true, RuleID: "LOCAL-SENSITIVE-MUTATION", Severity: "high", Reason: "sensitive path mutation"}
	}
	return DetectionDecision{}
}

func annotateDetection(event map[string]any, decision DetectionDecision) {
	metadata := eventMap(event, "metadata")
	if decision.Whitelist {
		metadata["whitelist_hit"] = true
		metadata["detection_rule_id"] = decision.RuleID
		metadata["detection_reason"] = decision.Reason
		event["metadata"] = metadata
		return
	}
	if !decision.Alert {
		return
	}
	metadata["security_alert"] = true
	if decision.Blacklist {
		metadata["blacklist_hit"] = true
	}
	metadata["detection_rule_id"] = decision.RuleID
	metadata["detection_severity"] = decision.Severity
	metadata["detection_reason"] = decision.Reason
	event["metadata"] = metadata
}
