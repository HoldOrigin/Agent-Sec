package collector

import (
	"testing"
	"time"
)

func TestRollingBufferPromotesOnlyOnAlertEvents(t *testing.T) {
	now := time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC)
	buffer := NewRollingBuffer(time.Minute, 1024*1024, 1024*1024)
	promotable := uploadTestEvent("file_create", "/tmp/payload", "", "/usr/bin/curl")
	local := uploadTestEvent("file_open", "/etc/hosts", "", "/usr/bin/cat")
	buffer.Add(promotable, now, true)
	buffer.Add(local, now.Add(time.Second), false)
	promoted, _ := buffer.Promote("cgroup:123", now.Add(2*time.Second))
	if len(promoted) != 1 || eventString(promoted[0], "event_type") != "file_create" {
		t.Fatalf("unexpected promoted events: %#v", promoted)
	}
	if snapshot := buffer.Snapshot("cgroup:123", now.Add(2*time.Second)); len(snapshot) != 1 || eventString(snapshot[0], "event_type") != "file_open" {
		t.Fatalf("LOCAL_ONLY event should remain in local buffer: %#v", snapshot)
	}
}

func TestRollingBufferAppliesTTLAndByteLimit(t *testing.T) {
	now := time.Date(2026, 8, 14, 0, 0, 0, 0, time.UTC)
	event := uploadTestEvent("file_create", "/tmp/payload", "", "/usr/bin/curl")
	buffer := NewRollingBuffer(time.Second, 1024, 1024)
	buffer.Add(event, now, true)
	if _, entries, _ := buffer.Stats(now.Add(2 * time.Second)); entries != 0 {
		t.Fatalf("expired entries=%d, want 0", entries)
	}
	small := NewRollingBuffer(time.Minute, 100, 100)
	if evicted := small.Add(event, now, true); evicted != 1 {
		t.Fatalf("oversized event evictions=%d, want 1", evicted)
	}
}
