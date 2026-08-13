package app_test

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"sentinel/internal/app"
)

func TestWebRCEPipeline(t *testing.T) {
	service := app.New(testConfig())
	result, err := service.IngestMany(loadDataset(t, "web_rce.jsonl"), true)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(result.Events); got != 6 {
		t.Fatalf("events=%d want=6", got)
	}
	if got := len(result.Behaviors); got != 8 {
		t.Fatalf("behaviors=%d want=8", got)
	}
	if got := len(result.Incidents); got != 1 {
		t.Fatalf("incidents=%d want=1", got)
	}
	incident := result.Incidents[0]
	if incident.Risk != "critical" || incident.Score != 100 {
		t.Fatalf("risk=%s score=%d", incident.Risk, incident.Score)
	}
	if incident.Classification != "likely_compromise" {
		t.Fatalf("classification=%s", incident.Classification)
	}
	if len(incident.AttackStory) != 7 {
		t.Fatalf("attack_story=%d want=7", len(incident.AttackStory))
	}
	if len(incident.ToolTrace) != 8 {
		t.Fatalf("tool_trace=%d want=8", len(incident.ToolTrace))
	}
	if incident.InvestigationStats.RawSyscallsSentToAI != 0 || !incident.InvestigationStats.CompressedInput {
		t.Fatal("agent input constraints not satisfied")
	}
	if incident.BlastRadius.ContainerCount != 1 {
		t.Fatalf("blast radius=%d", incident.BlastRadius.ContainerCount)
	}
	if len(service.Store.Alerts()) != 1 {
		t.Fatalf("alerts=%d want=1", len(service.Store.Alerts()))
	}
	policies := service.Collection.List()
	if len(policies) != 1 || policies[0].Level != "INVESTIGATION" {
		t.Fatalf("collection policy=%+v", policies)
	}
}

func TestNegativeSampleDoesNotCreateIncident(t *testing.T) {
	service := app.New(testConfig())
	result, err := service.IngestMany(loadDataset(t, "normal_ops.jsonl"), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Behaviors) != 1 || result.Behaviors[0].Type != "WebServerSpawnShell" {
		t.Fatalf("behaviors=%+v", result.Behaviors)
	}
	if len(result.Incidents) != 0 {
		t.Fatalf("incidents=%d want=0", len(result.Incidents))
	}
	if len(service.Store.Alerts()) != 0 {
		t.Fatalf("alerts=%d want=0", len(service.Store.Alerts()))
	}
	policies := service.Collection.List()
	if len(policies) != 1 || policies[0].Level != "WATCH" {
		t.Fatalf("collection policy=%+v", policies)
	}
}

func TestServiceInstancesAreIsolated(t *testing.T) {
	first := app.New(testConfig())
	second := app.New(testConfig())
	if _, err := first.IngestMany(loadDataset(t, "web_rce.jsonl"), true); err != nil {
		t.Fatal(err)
	}
	if second.Summary()["events"] != 0 || second.Summary()["incidents"] != 0 {
		t.Fatalf("second service leaked state: %+v", second.Summary())
	}
}

func loadDataset(t *testing.T, name string) []map[string]any {
	t.Helper()
	path := filepath.Join("..", "..", "datasets", name)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	result := []map[string]any{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var event map[string]any
		decoder := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		decoder.UseNumber()
		if err := decoder.Decode(&event); err != nil {
			t.Fatal(err)
		}
		result = append(result, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func testConfig() app.Config {
	return app.Config{Host: "127.0.0.1", Port: 8080, BodyLimit: 1_000_000, FileCacheTTL: time.Minute, CorrelationWindow: 5 * time.Minute, InvestigationWindow: 2 * time.Minute, MaxAgentSteps: 10}
}
