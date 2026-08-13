package httpapi

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"sentinel/internal/app"
	"sentinel/internal/behavior"
	"sentinel/internal/model"
	"sentinel/internal/policy"
)

type Handler struct {
	service  *app.Service
	root     string
	datasets map[string]Dataset
}
type Dataset struct {
	Name        string `json:"name"`
	File        string `json:"file"`
	Description string `json:"description"`
}

func New(service *app.Service, root string) http.Handler {
	return &Handler{service: service, root: root, datasets: map[string]Dataset{"web_rce": {Name: "Web RCE 后载荷执行", File: "web_rce.jsonl", Description: "下载、落地、授权、执行及 C2 外联"}, "normal_ops": {Name: "未完成攻击链负样本", File: "normal_ops.jsonl", Description: "只有 Web 进程派生 Shell，不生成 Incident"}}}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("x-request-id")
	if requestID == "" {
		requestID = randomID()
	}
	securityHeaders(w)
	w.Header().Set("x-request-id", requestID)
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var err error
	if r.URL.Path == "/metrics" {
		w.Header().Set("content-type", "text/plain; version=0.0.4; charset=utf-8")
		_, err = io.WriteString(w, h.service.Metrics())
	} else if strings.HasPrefix(r.URL.Path, "/api/") {
		err = h.api(w, r)
	} else {
		err = h.static(w, r)
	}
	if err != nil {
		h.writeError(w, err, requestID)
	}
}

func (h *Handler) api(w http.ResponseWriter, r *http.Request) error {
	path := r.URL.Path
	if r.Method == http.MethodGet {
		switch path {
		case "/api/health":
			return writeJSON(w, 200, map[string]any{"status": "ok", "version": app.Version, "implementation": "go", "components": map[string]string{"event_processor": "ok", "behavior_engine": "ok", "incident_engine": "ok", "investigation_agent": "ok"}})
		case "/api/summary":
			return writeJSON(w, 200, h.service.Summary())
		case "/api/datasets":
			return writeJSON(w, 200, h.datasets)
		case "/api/rules":
			return writeJSON(w, 200, behavior.Definitions)
		case "/api/events":
			return writeJSON(w, 200, h.service.Store.Events())
		case "/api/behaviors":
			return writeJSON(w, 200, h.service.Store.Behaviors())
		case "/api/alerts":
			return writeJSON(w, 200, h.service.Store.Alerts())
		case "/api/incidents":
			return writeJSON(w, 200, h.service.Store.Incidents())
		case "/api/collection-policies":
			return writeJSON(w, 200, h.service.Collection.List())
		case "/api/processor/stats":
			return writeJSON(w, 200, h.service.Processor.Stats())
		}
		if id, suffix, ok := incidentPath(path); ok {
			incident, exists := h.service.Store.Incident(id)
			if !exists {
				return app.NewError(404, "Incident not found")
			}
			if suffix == "" {
				return writeJSON(w, 200, incident)
			}
			if suffix == "graph" {
				return writeJSON(w, 200, incident.Graph)
			}
		}
	}
	if r.Method == http.MethodPost {
		switch path {
		case "/api/reset":
			h.service.Reset()
			return writeJSON(w, 200, map[string]bool{"ok": true})
		case "/api/events":
			var input map[string]any
			if err := h.decode(r, &input); err != nil {
				return err
			}
			result, err := h.service.Ingest(input, true)
			if err != nil {
				return err
			}
			return writeJSON(w, 201, result)
		case "/api/events/batch":
			var input struct {
				Reset  bool             `json:"reset"`
				Events []map[string]any `json:"events"`
			}
			if err := h.decode(r, &input); err != nil {
				return err
			}
			if input.Events == nil {
				return app.NewError(400, "events must be an array")
			}
			result, err := h.service.IngestMany(input.Events, input.Reset)
			if err != nil {
				return err
			}
			return writeJSON(w, 201, map[string]any{"events_received": len(input.Events), "events_ingested": len(result.Events), "behaviors_detected": len(result.Behaviors), "incidents_created": len(result.Incidents), "dropped": result.Dropped, "behaviors": result.Behaviors, "incidents": result.Incidents})
		case "/api/replay":
			var input struct {
				Dataset string `json:"dataset"`
				Reset   *bool  `json:"reset"`
			}
			if err := h.decode(r, &input); err != nil {
				return err
			}
			dataset, ok := h.datasets[input.Dataset]
			if !ok {
				return app.NewError(400, "Unknown dataset: "+input.Dataset)
			}
			events, err := readJSONL(filepath.Join(h.root, "datasets", dataset.File))
			if err != nil {
				return err
			}
			reset := true
			if input.Reset != nil {
				reset = *input.Reset
			}
			result, err := h.service.IngestMany(events, reset)
			if err != nil {
				return err
			}
			return writeJSON(w, 200, map[string]any{"dataset": input.Dataset, "events_received": len(events), "events_ingested": len(result.Events), "behaviors_detected": len(result.Behaviors), "alerts": len(h.service.Store.Alerts()), "collection_policies": h.service.Collection.List(), "processor_stats": h.service.Processor.Stats(), "behaviors": result.Behaviors, "incidents": result.Incidents})
		case "/api/alerts", "/api/agent/investigate":
			var input struct {
				IncidentID string `json:"incident_id"`
			}
			if err := h.decode(r, &input); err != nil {
				return err
			}
			if input.IncidentID == "" {
				return app.NewError(400, "AI 调查只能在 Incident 产生后触发，请提供 incident_id")
			}
			item, err := h.service.Investigate(input.IncidentID)
			if err != nil {
				return err
			}
			return writeJSON(w, 200, item)
		case "/api/actions/evaluate":
			var request policy.ActionRequest
			if err := h.decode(r, &request); err != nil {
				return err
			}
			decision, err := h.service.EvaluateAction(request)
			if err != nil {
				return err
			}
			return writeJSON(w, 200, decision)
		}
		if id, suffix, ok := incidentPath(path); ok && suffix == "rules/generate" {
			incident, exists := h.service.Store.Incident(id)
			if !exists {
				return app.NewError(404, "Incident not found")
			}
			return writeJSON(w, 200, candidateRule(incident))
		}
	}
	return app.NewError(404, "Route not found")
}

func (h *Handler) decode(r *http.Request, target any) error {
	data, err := io.ReadAll(io.LimitReader(r.Body, h.service.Config.BodyLimit+1))
	if err != nil {
		return app.NewError(400, "Failed to read request body")
	}
	if int64(len(data)) > h.service.Config.BodyLimit {
		return app.NewError(413, "Request body too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return app.NewError(400, "Invalid JSON body")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return app.NewError(400, "Request body must contain a single JSON value")
	}
	return nil
}
func (h *Handler) static(w http.ResponseWriter, r *http.Request) error {
	requested := strings.TrimPrefix(filepath.Clean(r.URL.Path), string(filepath.Separator))
	if requested == "." || requested == "" {
		requested = "index.html"
	}
	path := filepath.Join(h.root, "public", requested)
	publicRoot := filepath.Join(h.root, "public")
	relative, err := filepath.Rel(publicRoot, path)
	if err != nil || strings.HasPrefix(relative, "..") {
		return app.NewError(403, "Forbidden")
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return app.NewError(404, "Not found")
		}
		return err
	}
	http.ServeFile(w, r, path)
	return nil
}
func (h *Handler) writeError(w http.ResponseWriter, err error, requestID string) {
	status := 500
	var apiErr *app.Error
	if errors.As(err, &apiErr) {
		status = apiErr.Status
	}
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": "REQUEST_FAILED", "message": err.Error(), "request_id": requestID}})
}

func readJSONL(path string) ([]map[string]any, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	events := []map[string]any{}
	line := 0
	for scanner.Scan() {
		line++
		text := strings.TrimSpace(scanner.Text())
		if text == "" {
			continue
		}
		var event map[string]any
		decoder := json.NewDecoder(strings.NewReader(text))
		decoder.UseNumber()
		if err := decoder.Decode(&event); err != nil {
			return nil, app.NewError(400, fmt.Sprintf("Invalid JSONL at line %d", line))
		}
		events = append(events, event)
	}
	return events, scanner.Err()
}
func incidentPath(path string) (id, suffix string, ok bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 3 || parts[0] != "api" || parts[1] != "incidents" {
		return "", "", false
	}
	id = parts[2]
	if len(parts) > 3 {
		suffix = strings.Join(parts[3:], "/")
	}
	return id, suffix, true
}
func candidateRule(incident model.Incident) map[string]any {
	processes := []string{}
	paths := []string{}
	for _, node := range incident.Graph.Nodes {
		if node.Type == "process" {
			processes = appendUnique(processes, node.Label)
		}
		if node.Type == "file" {
			paths = appendUnique(paths, node.Label)
		}
	}
	return map[string]any{"status": "draft", "requires_review": true, "source_incident_id": incident.IncidentID, "rule": map[string]any{"id": "CAND-" + strings.ToUpper(incident.IncidentID), "title": "候选规则：" + incident.Title, "severity": incident.Risk, "condition": map[string]any{"process_any": processes, "file_path_any": paths, "within_seconds": 300}, "evidence_event_ids": incident.EvidenceEventIDs}}
}
func securityHeaders(w http.ResponseWriter) {
	w.Header().Set("access-control-allow-origin", "*")
	w.Header().Set("access-control-allow-headers", "content-type,x-request-id")
	w.Header().Set("access-control-allow-methods", "GET,POST,OPTIONS")
	w.Header().Set("x-content-type-options", "nosniff")
	w.Header().Set("referrer-policy", "no-referrer")
}
func writeJSON(w http.ResponseWriter, status int, payload any) error {
	w.Header().Set("content-type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(payload)
}
func randomID() string {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "request-unknown"
	}
	return hex.EncodeToString(data)
}
func appendUnique(values []string, value string) []string {
	for _, v := range values {
		if v == value {
			return values
		}
	}
	return append(values, value)
}
