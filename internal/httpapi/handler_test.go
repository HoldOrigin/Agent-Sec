package httpapi_test

import (
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
}
