package httpapi_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"sentinel/internal/app"
	"sentinel/internal/httpapi"
	"sentinel/internal/model"
)

func TestReplayAPIAndMetrics(t *testing.T) {
	config := app.Config{Host: "127.0.0.1", Port: 8080, BodyLimit: 1_000_000, FileCacheTTL: time.Minute, CorrelationWindow: 5 * time.Minute, InvestigationWindow: 2 * time.Minute, MaxAgentSteps: 10}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(httpapi.New(app.New(config), root))
	defer server.Close()
	response, err := http.Post(server.URL+"/api/replay", "application/json", strings.NewReader(`{"dataset":"web_rce"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("status=%d", response.StatusCode)
	}
	var replay struct {
		BehaviorsDetected int   `json:"behaviors_detected"`
		Incidents         []any `json:"incidents"`
	}
	if err := json.NewDecoder(response.Body).Decode(&replay); err != nil {
		t.Fatal(err)
	}
	if replay.BehaviorsDetected != 8 || len(replay.Incidents) != 1 {
		t.Fatalf("replay=%+v", replay)
	}
	metrics, err := http.Get(server.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer metrics.Body.Close()
	text, err := io.ReadAll(metrics.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(text), "runtime_behaviors 8") {
		t.Fatalf("metrics=%s", text)
	}
	if metrics.Header.Get("content-type") != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("content type=%s", metrics.Header.Get("content-type"))
	}
	health, err := http.Get(server.URL + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	defer health.Body.Close()
	var payload map[string]any
	if err := json.NewDecoder(health.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload["implementation"] != "go" {
		t.Fatalf("health=%+v", payload)
	}
	components, ok := payload["components"].(map[string]any)
	if !ok {
		t.Fatalf("health components=%+v", payload["components"])
	}
	storage, ok := components["storage"].(map[string]any)
	if !ok || storage["backend"] != "memory" || storage["durable"] != false {
		t.Fatalf("health storage=%+v", components["storage"])
	}
}

func TestBatchAPIAcceptsGzip(t *testing.T) {
	config := app.Config{Host: "127.0.0.1", Port: 8080, BodyLimit: 1_000_000, FileCacheTTL: time.Minute, CorrelationWindow: 5 * time.Minute, InvestigationWindow: 2 * time.Minute, MaxAgentSteps: 10}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(httpapi.New(app.New(config), root))
	defer server.Close()
	payload := `{"events":[{"event_id":"gzip-1","timestamp":"2026-08-14T00:00:00Z","event_type":"process_exec","host":{"host_id":"node-a","boot_id":"boot-a"},"process":{"pid":42,"ppid":1,"start_time":"2026-08-14T00:00:00Z","exe":"/bin/sh","argv":["/bin/sh"]},"parent_process":"nginx","metadata":{}}]}`
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, server.URL+"/api/events/batch", &compressed)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("content-type", "application/json")
	request.Header.Set("content-encoding", "gzip")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("status=%d body=%s", response.StatusCode, body)
	}
}

func TestAIInvestigationIsExplicitlyDisabledWithoutAPIKey(t *testing.T) {
	config := app.Config{Host: "127.0.0.1", Port: 8080, BodyLimit: 1_000_000, FileCacheTTL: time.Minute, CorrelationWindow: 5 * time.Minute, InvestigationWindow: 2 * time.Minute, MaxAgentSteps: 10}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(httpapi.New(app.New(config), root))
	defer server.Close()

	response, err := http.Post(server.URL+"/api/agent/investigate-ai", "application/json", strings.NewReader(`{"incident_id":"inc-missing"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusServiceUnavailable {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("status=%d body=%s", response.StatusCode, body)
	}
}

func TestCollectorBatchStoresEventsAndStructuredAlerts(t *testing.T) {
	config := app.Config{Host: "127.0.0.1", Port: 8080, BodyLimit: 1_000_000, FileCacheTTL: time.Minute, CorrelationWindow: 5 * time.Minute, InvestigationWindow: 2 * time.Minute, MaxAgentSteps: 10}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	service := app.New(config)
	server := httptest.NewServer(httpapi.New(service, root))
	defer server.Close()
	now := time.Now().UTC().Truncate(time.Microsecond)
	eventID := "evt-collector-alert-1"
	payload := map[string]any{
		"events": []map[string]any{{
			"event_id": eventID, "timestamp": now.Format(time.RFC3339Nano), "event_type": "process_exec",
			"host":      map[string]any{"host_id": "node-a", "boot_id": "boot-a"},
			"process":   map[string]any{"pid": 77, "ppid": 1, "exe": "/tmp/payload", "argv": []string{"/tmp/payload"}, "start_time": now.Format(time.RFC3339Nano)},
			"container": map[string]any{"container_id": "container-a"},
			"metadata":  map[string]any{"security_alert": true, "detection_rule_id": "LOCAL-TEMP-EXEC", "detection_severity": "critical", "detection_reason": "temporary path execution"},
		}},
		"alerts": []model.Alert{{AlertID: "alt-collector-test", Title: "Collector local detection: LOCAL-TEMP-EXEC", Description: "temporary path execution", Severity: "critical", Source: "collector", HostID: "node-a", ContainerID: "container-a", RuleIDs: []string{"LOCAL-TEMP-EXEC"}, EventIDs: []string{eventID}, EventID: eventID, CorrelationKey: "B900:" + eventID, Status: "open", CreatedAt: now, UpdatedAt: now}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.Post(server.URL+"/api/collector/batch", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		data, _ := io.ReadAll(response.Body)
		t.Fatalf("status=%d body=%s", response.StatusCode, data)
	}
	alerts := service.Store.Alerts()
	if len(alerts) != 1 || alerts[0].Source != "collector" || alerts[0].HostID != "node-a" || alerts[0].RuleIDs[0] != "LOCAL-TEMP-EXEC" {
		t.Fatalf("alerts=%+v", alerts)
	}
	for _, path := range []string{
		"/api/events/" + eventID,
		"/api/events?type=process_exec&host_id=node-a&container_id=container-a&limit=10",
		"/api/alerts/" + alerts[0].AlertID,
		"/api/alerts?severity=critical&status=open&source=collector&host_id=node-a&limit=10",
	} {
		result, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		result.Body.Close()
		if result.StatusCode != http.StatusOK {
			t.Fatalf("GET %s status=%d", path, result.StatusCode)
		}
	}
}
