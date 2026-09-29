//go:build integration

package store

import (
	"context"
	"os"
	"testing"
	"time"

	"sentinel/internal/model"
)

// This test intentionally resets all Agent-Sec tables. Point
// TEST_DATABASE_URL only at a disposable test database.
func TestPostgresRoundTripAndReload(t *testing.T) {
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	repository, err := NewPostgres(ctx, url, PostgresOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.Reset(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = repository.Reset()
		_ = repository.Close()
	})

	now := time.Now().UTC().Truncate(time.Microsecond)
	event := model.RuntimeEvent{EventID: "evt-pg-1", Timestamp: now, Type: "process_exec", Host: "host-a", PID: 42, Process: "sh", ProcessEntityID: "proc-1", Metadata: map[string]any{"source": "integration"}}
	if _, err := repository.AddEvent(event); err != nil {
		t.Fatal(err)
	}
	behavior := model.Behavior{BehaviorID: "beh-pg-1", Code: "B001", Type: "WebServerSpawnShell", Timestamp: now, Scope: model.Scope{HostID: "host-a"}, CorrelationKey: "host-a:", Evidence: []string{event.EventID}}
	if err := repository.ReplaceBehaviors([]model.Behavior{behavior}); err != nil {
		t.Fatal(err)
	}
	alert := model.Alert{AlertID: "alt-pg-1", Title: "test", Description: "integration alert", Severity: "high", Source: "collector", HostID: "host-a", ContainerID: "container-a", Status: "open", CorrelationKey: "host-a:", EventID: event.EventID, EventIDs: []string{event.EventID}, CreatedAt: now, UpdatedAt: now}
	if _, err := repository.AddAlert(alert); err != nil {
		t.Fatal(err)
	}
	incident := model.Incident{IncidentID: "inc-pg-1", AlertID: alert.AlertID, Severity: "high", Status: "open", HostID: "host-a", StartTime: now, EndTime: now, EvidenceEventIDs: []string{event.EventID}}
	if _, err := repository.AddIncident(incident); err != nil {
		t.Fatal(err)
	}
	if err := repository.Close(); err != nil {
		t.Fatal(err)
	}

	reloaded, err := NewPostgres(ctx, url, PostgresOptions{})
	if err != nil {
		t.Fatal(err)
	}
	repository = reloaded
	if got := len(reloaded.Events()); got != 1 {
		t.Fatalf("events after reload = %d, want 1", got)
	}
	if got := len(reloaded.Behaviors()); got != 1 {
		t.Fatalf("behaviors after reload = %d, want 1", got)
	}
	if got := len(reloaded.Alerts()); got != 1 {
		t.Fatalf("alerts after reload = %d, want 1", got)
	}
	if got := reloaded.Alerts()[0]; got.Source != "collector" || got.HostID != "host-a" || got.Description != "integration alert" {
		t.Fatalf("alert after reload = %+v", got)
	}
	if got := len(reloaded.Incidents()); got != 1 {
		t.Fatalf("incidents after reload = %d, want 1", got)
	}
}
