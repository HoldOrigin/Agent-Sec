package processor_test

import (
	"testing"
	"time"

	"sentinel/internal/processor"
)

func TestNestedEventNormalizationAndStableIdentity(t *testing.T) {
	p := processor.New(time.Minute)
	base := map[string]any{
		"event_id": "nested-001", "timestamp": float64(1720000000), "event_type": "process_exec",
		"host":      map[string]any{"host_id": "host-001", "boot_id": "boot-123"},
		"process":   map[string]any{"pid": float64(1234), "ppid": float64(1000), "start_time": float64(1720000000), "exe": "/usr/bin/curl", "argv": []any{"curl", "http://1.2.3.4/a"}, "uid": float64(1000)},
		"container": map[string]any{"container_id": "ctr-1", "workload": "payment-api"},
	}
	first, err := p.Process(base)
	if err != nil {
		t.Fatal(err)
	}
	if got := first.Accepted[0].ProcessEntityID; got != "proc://host-001/boot-123/1234/1720000000" {
		t.Fatalf("process id=%s", got)
	}
	secondInput := clone(base)
	secondInput["event_id"] = "nested-002"
	secondInput["timestamp"] = float64(1720000001)
	process := secondInput["process"].(map[string]any)
	delete(process, "start_time")
	second, err := p.Process(secondInput)
	if err != nil {
		t.Fatal(err)
	}
	if second.Accepted[0].ProcessEntityID != first.Accepted[0].ProcessEntityID {
		t.Fatalf("identity changed: %s vs %s", first.Accepted[0].ProcessEntityID, second.Accepted[0].ProcessEntityID)
	}
}

func TestHighVolumeFileOpenIsFiltered(t *testing.T) {
	p := processor.New(time.Minute)
	result, err := p.Process(map[string]any{"event_id": "open-001", "timestamp": "2026-08-10T12:00:00Z", "type": "file_open", "host": "node-1", "pid": float64(10), "ppid": float64(1), "process": "cat", "metadata": map[string]any{"path": "/usr/share/locale/messages.mo"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Dropped != "agent_filter" || len(result.Accepted) != 0 {
		t.Fatalf("result=%+v", result)
	}
}

func clone(input map[string]any) map[string]any {
	result := map[string]any{}
	for key, value := range input {
		if nested, ok := value.(map[string]any); ok {
			copy := map[string]any{}
			for k, v := range nested {
				copy[k] = v
			}
			result[key] = copy
		} else {
			result[key] = value
		}
	}
	return result
}
