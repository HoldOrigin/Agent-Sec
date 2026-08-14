package collector

import "testing"

func TestDefaultUploadPolicyModes(t *testing.T) {
	policy := NewDefaultUploadPolicy()
	detection := NewDefaultDetectionPolicy()
	tests := []struct {
		name  string
		event map[string]any
		mode  UploadMode
	}{
		{"file open is local", uploadTestEvent("file_open", "/etc/hosts", "", "/usr/bin/cat"), UploadLocalOnly},
		{"internal connect aggregates", uploadTestEvent("network_connect", "", "10.2.3.4", "/usr/bin/app"), UploadAggregate},
		{"external connect is alert context", uploadTestEvent("network_connect", "", "8.8.8.8", "/usr/bin/app"), UploadOnAlert},
		{"normal exec is retained", uploadTestEvent("process_exec", "", "", "/usr/bin/app"), UploadOnAlert},
		{"temporary exec is immediate", uploadTestEvent("process_exec", "", "", "/tmp/payload"), UploadAlways},
		{"sensitive mutation is immediate", uploadTestEvent("file_create", "/etc/cron.d/job", "", "/usr/bin/app"), UploadAlways},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			annotateDetection(test.event, detection.Evaluate(test.event))
			if decision := policy.Decide(test.event); decision.Mode != test.mode {
				t.Fatalf("got mode %s (%s), want %s", decision.Mode, decision.Reason, test.mode)
			}
		})
	}
}

func TestDefaultUploadPolicyHonorsInvestigationAndSecurityAlert(t *testing.T) {
	policy := NewDefaultUploadPolicy()
	event := uploadTestEvent("file_open", "/var/lib/app/data", "", "/usr/bin/app")
	eventMap(event, "metadata")["collection_level"] = "INVESTIGATION"
	if decision := policy.Decide(event); decision.Mode != UploadAlways || decision.PromoteContext {
		t.Fatalf("unexpected investigation decision: %+v", decision)
	}
	eventMap(event, "metadata")["security_alert"] = true
	if decision := policy.Decide(event); decision.Mode != UploadAlways || !decision.PromoteContext {
		t.Fatalf("unexpected security alert decision: %+v", decision)
	}
}

func uploadTestEvent(eventType, path, destination, executable string) map[string]any {
	return map[string]any{
		"event_id":   "evt-test",
		"event_type": eventType,
		"timestamp":  "2026-08-14T00:00:00Z",
		"host":       map[string]any{"host_id": "node-a", "boot_id": "boot-a"},
		"process":    map[string]any{"pid": uint32(42), "exe": executable},
		"container":  map[string]any{"cgroup_id": "123", "container_id": "container-a"},
		"metadata": map[string]any{
			"path":             path,
			"destination_ip":   destination,
			"destination_port": 443,
			"protocol":         "tcp",
			"exec_path":        executable,
			"collection_level": "NORMAL",
		},
	}
}
