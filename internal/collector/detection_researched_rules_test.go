package collector

import (
	"os"
	"testing"
)

func TestResearchedDetectionRulesCompileAndMatch(t *testing.T) {
	data, err := os.ReadFile("../../configs/detection-rules-researched.yaml")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := NewCELDetectionPolicy(data, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Version() != "research-v1" {
		t.Fatalf("version=%q", policy.Version())
	}

	t.Run("netcat remote execution", func(t *testing.T) {
		event := uploadTestEvent("process_exec", "", "", "/usr/bin/nc")
		eventMap(event, "process")["argv"] = []string{"/usr/bin/nc", "-e"}
		decision := policy.Evaluate(event)
		if !decision.Blacklist || decision.RuleID != "BL-NETCAT-RCE-CONTAINER" {
			t.Fatalf("unexpected decision: %+v", decision)
		}
	})

	t.Run("scheduled task persistence", func(t *testing.T) {
		event := uploadTestEvent("file_create", "/etc/cron.d/persistence", "", "/usr/bin/sh")
		decision := policy.Evaluate(event)
		if !decision.Blacklist || decision.RuleID != "BL-SCHEDULED-TASK-CREATE" {
			t.Fatalf("unexpected decision: %+v", decision)
		}
	})

	t.Run("normal executable does not match", func(t *testing.T) {
		event := uploadTestEvent("process_exec", "", "", "/usr/bin/true")
		decision := policy.Evaluate(event)
		if decision.Blacklist {
			t.Fatalf("unexpected blacklist decision: %+v", decision)
		}
	})
}
