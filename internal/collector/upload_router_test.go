package collector

import (
	"testing"
	"time"
)

func TestUploadRouterPromotesPreAndPostAlertContext(t *testing.T) {
	now := time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC)
	metrics := &Metrics{}
	router := NewUploadRouter(UploadRouterConfig{BufferTTL: time.Minute, BufferMaxBytes: 1024 * 1024, BufferMaxBytesPerScope: 1024 * 1024, AggregateWindow: time.Minute, PostAlertWindow: time.Minute}, nil, nil, metrics)
	file := uploadTestEvent("file_create", "/tmp/payload", "", "/usr/bin/curl")
	file["event_id"] = "file"
	if routed := router.Process(file, now); len(routed) != 0 {
		t.Fatalf("ON_ALERT file should be buffered: %#v", routed)
	}
	exec := uploadTestEvent("process_exec", "", "", "/tmp/payload")
	exec["event_id"] = "exec"
	routed := router.Process(exec, now.Add(time.Second))
	if len(routed) != 2 || routed[0].Event["event_id"] != "file" || routed[1].Event["event_id"] != "exec" {
		t.Fatalf("unexpected pre-alert promotion: %#v", routed)
	}
	connect := uploadTestEvent("network_connect", "", "8.8.8.8", "/tmp/payload")
	connect["event_id"] = "connect"
	routed = router.Process(connect, now.Add(2*time.Second))
	if len(routed) != 1 || routed[0].Priority != PriorityHigh || eventMap(routed[0].Event, "metadata")["upload_reason"] != "post_alert_context" {
		t.Fatalf("unexpected post-alert upload: %#v", routed)
	}
	if metrics.ContextPromoted.Load() != 1 || metrics.ActiveAlertScopes.Load() != 1 {
		t.Fatalf("unexpected metrics: promoted=%d active=%d", metrics.ContextPromoted.Load(), metrics.ActiveAlertScopes.Load())
	}
}

func TestUploadRouterAggregatesStableNetworkEvents(t *testing.T) {
	now := time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC)
	metrics := &Metrics{}
	router := NewUploadRouter(UploadRouterConfig{AggregateWindow: time.Minute, MaxAggregateKeys: 10}, nil, nil, metrics)
	first := uploadTestEvent("network_connect", "", "10.2.3.4", "/usr/bin/app")
	second := cloneEvent(first)
	second["event_id"] = "evt-two"
	if routed := router.Process(first, now); len(routed) != 0 {
		t.Fatalf("first aggregate input should not upload immediately: %#v", routed)
	}
	if routed := router.Process(second, now.Add(time.Second)); len(routed) != 0 {
		t.Fatalf("second aggregate input should not upload immediately: %#v", routed)
	}
	routed := router.Flush(now.Add(2*time.Second), true)
	if len(routed) != 1 {
		t.Fatalf("aggregate flush returned %d events, want 1", len(routed))
	}
	metadata := eventMap(routed[0].Event, "metadata")
	if metadata["aggregate_count"] != uint64(2) || routed[0].Priority != PriorityNormal {
		t.Fatalf("unexpected aggregate: %#v", routed[0])
	}
	if metrics.AggregateInput.Load() != 2 || metrics.AggregateOutput.Load() != 1 {
		t.Fatalf("unexpected aggregate metrics")
	}
}

func TestUploadRouterKeepsOnlyLocalSummary(t *testing.T) {
	now := time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC)
	metrics := &Metrics{}
	router := NewUploadRouter(UploadRouterConfig{AggregateWindow: time.Second, MaxAggregateKeys: 10, BufferTTL: time.Minute, BufferMaxBytes: 1024 * 1024, BufferMaxBytesPerScope: 1024 * 1024}, nil, nil, metrics)
	first := uploadTestEvent("file_open", "/var/lib/app/data", "", "/usr/bin/app")
	second := cloneEvent(first)
	second["event_id"] = "evt-two"
	if routed := router.Process(first, now); len(routed) != 0 {
		t.Fatalf("LOCAL_ONLY event was uploaded: %#v", routed)
	}
	if routed := router.Process(second, now.Add(100*time.Millisecond)); len(routed) != 0 {
		t.Fatalf("LOCAL_ONLY duplicate was uploaded: %#v", routed)
	}
	if routed := router.Flush(now.Add(2*time.Second), false); len(routed) != 0 {
		t.Fatalf("LOCAL_ONLY summary was uploaded: %#v", routed)
	}
	snapshot := router.buffer.Snapshot("cgroup:123", now.Add(2*time.Second))
	if len(snapshot) != 1 {
		t.Fatalf("local summary count=%d, want 1", len(snapshot))
	}
	metadata := eventMap(snapshot[0], "metadata")
	if metadata["aggregate_count"] != uint64(2) || metadata["upload_mode"] != string(UploadLocalOnly) {
		t.Fatalf("unexpected local summary: %#v", metadata)
	}
}
