package collector

import "testing"

func TestDefaultDetectionPolicyDenyOverridesAllow(t *testing.T) {
	policy := NewDefaultDetectionPolicy()
	event := uploadTestEvent("process_exec", "", "", "/tmp/payload")
	metadata := eventMap(event, "metadata")
	metadata["whitelist_hit"] = true
	if decision := policy.Evaluate(event); decision.Alert {
		t.Fatalf("whitelist should suppress built-in heuristic: %+v", decision)
	}
	metadata["blacklist_hit"] = true
	if decision := policy.Evaluate(event); !decision.Alert || decision.RuleID != "LOCAL-BLACKLIST" {
		t.Fatalf("blacklist should override whitelist: %+v", decision)
	}
}

func TestDefaultDetectionPolicyRecognizesWebShell(t *testing.T) {
	policy := NewDefaultDetectionPolicy()
	event := uploadTestEvent("process_exec", "", "", "/bin/sh")
	event["parent_process"] = "nginx"
	decision := policy.Evaluate(event)
	if !decision.Alert || decision.RuleID != "LOCAL-WEB-SHELL" {
		t.Fatalf("unexpected decision: %+v", decision)
	}
}
