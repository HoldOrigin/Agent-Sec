package domain

import (
	"encoding/json"
	"testing"
	"time"
)

func validEvent() Event {
	now := time.Now().UTC()
	return Event{ID: "e1", SchemaVersion: 1, TenantID: "t1", SensorID: "s1", HostID: "h1",
		BootID: "b1", Kind: EventProcessExec, Outcome: OutcomeSuccess, ObservedAt: now,
		IngestedAt: now, Details: json.RawMessage(`{"executable":"/bin/sh"}`)}
}

func TestEventValidation(t *testing.T) {
	e := validEvent()
	if err := e.Validate(); err != nil {
		t.Fatalf("valid event rejected: %v", err)
	}
	e.Kind = "MADE_UP"
	if err := e.Validate(); err == nil {
		t.Fatal("unknown event kind accepted")
	}
}

func TestScopeContains(t *testing.T) {
	e := validEvent()
	s := Scope{TenantID: "t1", Start: e.ObservedAt.Add(-time.Minute), End: e.ObservedAt.Add(time.Minute), AllowedHosts: []string{"h1"}}
	if !s.Contains(e) {
		t.Fatal("in-scope event rejected")
	}
	e.TenantID = "other"
	if s.Contains(e) {
		t.Fatal("cross-tenant event accepted")
	}
}

func TestScopeContainsEnforcesWorkload(t *testing.T) {
	now := time.Now().UTC()
	scope := Scope{TenantID: "t1", Start: now.Add(-time.Minute), End: now.Add(time.Minute), AllowedHosts: []string{"h1"}, AllowedWorkloads: []string{"container-a"}}
	event := validEvent()
	event.ObservedAt, event.ContainerID = now, "container-b"
	if scope.Contains(event) {
		t.Fatal("different workload escaped scope")
	}
	event.ContainerID = "container-a"
	if !scope.Contains(event) {
		t.Fatal("allowed workload was rejected")
	}
}
