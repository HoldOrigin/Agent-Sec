package collector

import (
	"os"
	"testing"
)

func TestCELDetectionPolicyDenyOverridesAllow(t *testing.T) {
	bundle := []byte(`
version: test-v1
rules:
  - id: BL-TEMP
    kind: blacklist
    priority: 10
    severity: critical
    condition: event.process.exe.startsWith("/tmp/")
  - id: WL-TEMP
    kind: whitelist
    priority: 100
    condition: event.process.exe.startsWith("/tmp/")
`)
	metrics := &Metrics{}
	policy, err := NewCELDetectionPolicy(bundle, nil, metrics)
	if err != nil {
		t.Fatal(err)
	}
	decision := policy.Evaluate(uploadTestEvent("process_exec", "", "", "/tmp/payload"))
	if !decision.Alert || !decision.Blacklist || decision.RuleID != "BL-TEMP" {
		t.Fatalf("unexpected decision: %+v", decision)
	}
	if metrics.BlacklistHits.Load() != 1 || metrics.WhitelistHits.Load() != 0 {
		t.Fatalf("unexpected hit metrics")
	}
}

func TestCELDetectionPolicyWhitelistAndAtomicReload(t *testing.T) {
	bundle := []byte(`
version: test-v1
rules:
  - id: WL-APP
    kind: whitelist
    condition: event.process.exe == "/usr/bin/app"
`)
	policy, err := NewCELDetectionPolicy(bundle, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	decision := policy.Evaluate(uploadTestEvent("process_exec", "", "", "/usr/bin/app"))
	if !decision.Whitelist || decision.RuleID != "WL-APP" {
		t.Fatalf("unexpected whitelist decision: %+v", decision)
	}
	if err := policy.Reload([]byte("version: broken\nrules:\n  - unknown: true\n")); err == nil {
		t.Fatal("expected invalid reload to fail")
	}
	if policy.Version() != "test-v1" {
		t.Fatalf("failed reload replaced active snapshot: %s", policy.Version())
	}
}

func TestRepositoryDetectionRulesCompile(t *testing.T) {
	data, err := os.ReadFile("../../configs/detection-rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewCELDetectionPolicy(data, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Version() != "mvp-v1" {
		t.Fatalf("version=%q", policy.Version())
	}
	decision := policy.Evaluate(uploadTestEvent("process_exec", "", "", "/tmp/repository-rule-test"))
	if !decision.Blacklist || decision.RuleID != "BL-TEMP-EXEC" || decision.Severity != "critical" {
		t.Fatalf("repository blacklist did not match: %+v", decision)
	}
}
