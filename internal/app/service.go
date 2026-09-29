package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	agentic "sentinel/internal/agentic"
	"sentinel/internal/behavior"
	"sentinel/internal/collection"
	"sentinel/internal/incident"
	"sentinel/internal/investigation"
	"sentinel/internal/model"
	"sentinel/internal/policy"
	"sentinel/internal/processor"
	"sentinel/internal/store"
)

type Service struct {
	Config     Config
	Store      store.Repository
	Processor  *processor.Processor
	Behavior   *behavior.Engine
	Incident   *incident.Engine
	Collection *collection.Manager
	Policy     *policy.Engine
	Agent      *investigation.Agent
	AIAgent    *agentic.Runtime
	AIError    error
}
type PipelineResult struct {
	Events    []model.RuntimeEvent `json:"events"`
	Dropped   []map[string]string  `json:"dropped,omitempty"`
	Behaviors []model.Behavior     `json:"behaviors"`
	Incidents []model.Incident     `json:"incidents"`
	Processor model.ProcessResult  `json:"processor,omitempty"`
}

type CollectorBatchResult struct {
	Pipeline PipelineResult `json:"pipeline"`
	Alerts   []model.Alert  `json:"alerts"`
}

func New(config Config) *Service {
	return NewWithStore(config, store.NewMemory())
}

func NewWithStore(config Config, repository store.Repository) *Service {
	s := &Service{Config: config, Store: repository, Processor: processor.New(config.FileCacheTTL), Behavior: behavior.New(), Incident: incident.New(config.CorrelationWindow), Collection: collection.New(config.InvestigationWindow), Policy: policy.New()}
	s.Agent = investigation.New(s.Store, s.Policy, config.MaxAgentSteps)
	if strings.TrimSpace(config.QwenAPIKey) != "" {
		s.AIAgent, s.AIError = agentic.NewRuntime(s.Store, agentic.RuntimeConfig{
			APIKey: config.QwenAPIKey, PlannerModel: config.PlannerModel, ExecutorModel: config.ExecutorModel,
			AnalyzerModel: config.AnalyzerModel, AuditPath: config.AgentAuditPath,
			MaxDecisions: config.MaxAgentDecisions, MaxToolCalls: config.MaxAgentToolCalls,
			Window: config.CorrelationWindow,
		})
	}
	return s
}
func (s *Service) Reset() error {
	if err := s.Store.Reset(); err != nil {
		return fmt.Errorf("reset repository: %w", err)
	}
	s.Processor.Reset()
	s.Collection.Reset()
	return nil
}
func (s *Service) Ingest(input map[string]any, run bool) (PipelineResult, error) {
	processed, err := s.Processor.Process(input)
	if err != nil {
		return PipelineResult{}, err
	}
	events := []model.RuntimeEvent{}
	for _, event := range processed.Accepted {
		if err := validateEvent(event); err != nil {
			return PipelineResult{}, err
		}
		stored, err := s.Store.AddEvent(event)
		if err != nil {
			return PipelineResult{}, fmt.Errorf("store event %s: %w", event.EventID, err)
		}
		events = append(events, stored)
	}
	result := PipelineResult{Events: events, Processor: processed}
	if run {
		behaviors, incidents, err := s.RunPipeline()
		result.Behaviors = behaviors
		result.Incidents = incidents
		return result, err
	}
	return result, nil
}
func (s *Service) IngestMany(inputs []map[string]any, reset bool) (PipelineResult, error) {
	if reset {
		if err := s.Reset(); err != nil {
			return PipelineResult{}, err
		}
	}
	result := PipelineResult{Events: []model.RuntimeEvent{}, Dropped: []map[string]string{}}
	for _, input := range inputs {
		item, err := s.Ingest(input, false)
		if err != nil {
			return PipelineResult{}, err
		}
		result.Events = append(result.Events, item.Events...)
		if item.Processor.Dropped != "" {
			result.Dropped = append(result.Dropped, map[string]string{"event_id": stringValue(input["event_id"]), "reason": item.Processor.Dropped})
		}
	}
	behaviors, incidents, err := s.RunPipeline()
	result.Behaviors = behaviors
	result.Incidents = incidents
	return result, err
}
func (s *Service) RunPipeline() ([]model.Behavior, []model.Incident, error) {
	events := s.Store.Events()
	behaviors := s.Behavior.Derive(events)
	if err := s.Store.ReplaceBehaviors(behaviors); err != nil {
		return nil, nil, fmt.Errorf("store behaviors: %w", err)
	}
	s.Collection.ObserveBehaviors(behaviors)
	for _, item := range behaviors {
		if item.Type != "LocalSecurityPolicyMatch" {
			continue
		}
		eventID := ""
		if len(item.Evidence) > 0 {
			eventID = item.Evidence[0]
		}
		now := item.Timestamp
		if now.IsZero() {
			now = time.Now().UTC()
		}
		severity := normalizedSeverity(detailString(item.Details, "severity"))
		ruleID := detailString(item.Details, "rule_id")
		if ruleID == "" {
			ruleID = "LOCAL-DETECTION"
		}
		if _, err := s.Store.AddAlert(model.Alert{
			AlertID:        "alt-" + strings.TrimPrefix(item.BehaviorID, "beh-"),
			Title:          "Local runtime security policy matched",
			Description:    detailString(item.Details, "reason"),
			Severity:       severity,
			Source:         "server",
			HostID:         item.Scope.HostID,
			ContainerID:    item.Scope.ContainerID,
			RuleIDs:        []string{ruleID},
			EventIDs:       append([]string{}, item.Evidence...),
			EventID:        eventID,
			CorrelationKey: item.CorrelationKey,
			Status:         "open",
			CreatedAt:      now,
			UpdatedAt:      now,
		}); err != nil {
			return nil, nil, fmt.Errorf("store local alert: %w", err)
		}
	}
	correlated := s.Incident.Correlate(behaviors, events)
	s.Collection.ObserveIncidents(correlated)
	incidents := []model.Incident{}
	for _, base := range correlated {
		now := base.StartTime
		alert, err := s.Store.AddAlert(model.Alert{AlertID: "alt-" + strings.TrimPrefix(base.IncidentID, "inc-"), Title: "Web RCE Payload Execution Pattern", Severity: base.Severity, Source: "server", HostID: base.HostID, ContainerID: base.ContainerID, RuleIDs: []string{"PATTERN-WEB-RCE-001"}, EventIDs: []string{base.EvidenceEventIDs[0]}, EventID: base.EvidenceEventIDs[0], CorrelationKey: base.HostID + ":" + base.ContainerID, Status: "open", CreatedAt: now, UpdatedAt: now})
		if err != nil {
			return nil, nil, fmt.Errorf("store correlated alert: %w", err)
		}
		base.AlertID = alert.AlertID
		investigated, err := s.Agent.Investigate(base)
		if err != nil {
			return nil, nil, err
		}
		incidents = append(incidents, investigated)
	}
	return behaviors, incidents, nil
}

func (s *Service) IngestCollectorBatch(inputs []map[string]any, alerts []model.Alert) (CollectorBatchResult, error) {
	pipeline := PipelineResult{Events: []model.RuntimeEvent{}, Behaviors: []model.Behavior{}, Incidents: []model.Incident{}}
	var err error
	if len(inputs) > 0 {
		pipeline, err = s.IngestMany(inputs, false)
		if err != nil {
			return CollectorBatchResult{}, err
		}
	}
	stored := make([]model.Alert, 0, len(alerts))
	for _, alert := range alerts {
		if alert.EventID == "" {
			return CollectorBatchResult{}, NewError(400, "alert event_id is required")
		}
		event, ok := s.Store.Event(alert.EventID)
		if !ok {
			return CollectorBatchResult{}, NewError(400, "alert references unknown event_id: "+alert.EventID)
		}
		normalized, err := normalizeCollectorAlert(alert, event)
		if err != nil {
			return CollectorBatchResult{}, err
		}
		saved, err := s.Store.AddAlert(normalized)
		if err != nil {
			return CollectorBatchResult{}, fmt.Errorf("store collector alert %s: %w", alert.AlertID, err)
		}
		stored = append(stored, saved)
	}
	return CollectorBatchResult{Pipeline: pipeline, Alerts: stored}, nil
}

func normalizeCollectorAlert(alert model.Alert, event model.RuntimeEvent) (model.Alert, error) {
	if alert.AlertID == "" {
		return model.Alert{}, NewError(400, "alert_id is required")
	}
	if alert.EventID == "" {
		return model.Alert{}, NewError(400, "alert event_id is required")
	}
	if len(alert.RuleIDs) == 0 || strings.TrimSpace(alert.RuleIDs[0]) == "" {
		return model.Alert{}, NewError(400, "alert rule_ids is required")
	}
	alert.Severity = normalizedSeverity(alert.Severity)
	alert.Source = "collector"
	alert.HostID = firstString(alert.HostID, event.HostID, event.Host)
	alert.ContainerID = firstString(alert.ContainerID, event.ContainerID)
	if alert.Title == "" {
		alert.Title = "Collector local detection: " + alert.RuleIDs[0]
	}
	alert.EventIDs = appendUniqueString(alert.EventIDs, alert.EventID)
	alert.CorrelationKey = "B900:" + alert.EventID
	if alert.Status == "" {
		alert.Status = "open"
	}
	if alert.Status != "open" && alert.Status != "closed" {
		return model.Alert{}, NewError(400, "alert status must be open or closed")
	}
	if alert.CreatedAt.IsZero() {
		alert.CreatedAt = event.Timestamp
	}
	if alert.UpdatedAt.IsZero() {
		alert.UpdatedAt = alert.CreatedAt
	}
	return alert, nil
}
func (s *Service) Investigate(id string) (model.Incident, error) {
	item, ok := s.Store.Incident(id)
	if !ok {
		return model.Incident{}, NewError(404, "Incident not found")
	}
	return s.Agent.Investigate(item)
}

func (s *Service) InvestigateAI(ctx context.Context, id string) (agentic.RunResult, error) {
	if s.AIError != nil {
		return agentic.RunResult{}, NewError(503, "AI Agent 初始化失败: "+s.AIError.Error())
	}
	if s.AIAgent == nil {
		return agentic.RunResult{}, NewError(503, "AI Agent 未启用，请设置 QWEN_API_KEY")
	}
	item, ok := s.Store.Incident(id)
	if !ok {
		return agentic.RunResult{}, NewError(404, "Incident not found")
	}
	return s.AIAgent.Investigate(ctx, item)
}

func (s *Service) AIStatus() map[string]any {
	status := map[string]any{"enabled": s.AIAgent != nil && s.AIError == nil}
	if s.AIAgent != nil {
		status["models"] = s.AIAgent.Models()
	}
	if s.AIError != nil {
		status["error"] = s.AIError.Error()
	}
	return status
}
func (s *Service) StorageStatus() map[string]any {
	return map[string]any{"backend": s.Store.Name(), "durable": s.Store.Name() == "postgresql"}
}
func (s *Service) EvaluateAction(request policy.ActionRequest) (model.PolicyDecision, error) {
	if request.Action == "" {
		return model.PolicyDecision{}, NewError(400, "action is required")
	}
	return s.Policy.Evaluate(request), nil
}
func (s *Service) Summary() map[string]int {
	incidents := s.Store.Incidents()
	critical := 0
	approvals := 0
	for _, item := range incidents {
		if item.Risk == "critical" {
			critical++
		}
		for _, rec := range item.Recommendations {
			if rec.Policy.Decision == "require_approval" {
				approvals++
			}
		}
	}
	return map[string]int{"events": len(s.Store.Events()), "behaviors": len(s.Store.Behaviors()), "alerts": len(s.Store.Alerts()), "incidents": len(incidents), "critical": critical, "pending_approval": approvals}
}
func (s *Service) Metrics() string {
	stats := s.Processor.Stats()
	levels := map[string]int{"NORMAL": 0, "WATCH": 0, "INVESTIGATION": 0}
	for _, item := range s.Collection.List() {
		levels[item.Level]++
	}
	return fmt.Sprintf("# HELP runtime_events_received_total Runtime events received before filtering.\n# TYPE runtime_events_received_total counter\nruntime_events_received_total %d\n# HELP runtime_events_accepted_total Runtime events retained by the processor.\n# TYPE runtime_events_accepted_total counter\nruntime_events_accepted_total %d\nruntime_events_filtered_total %d\nruntime_events_deduplicated_total %d\nruntime_file_events_promoted_total %d\n# TYPE runtime_behaviors gauge\nruntime_behaviors %d\n# TYPE runtime_incidents gauge\nruntime_incidents %d\nruntime_collection_scopes{level=\"normal\"} %d\nruntime_collection_scopes{level=\"watch\"} %d\nruntime_collection_scopes{level=\"investigation\"} %d\n", stats.Received, stats.Accepted, stats.Filtered, stats.Deduplicated, stats.Promoted, len(s.Store.Behaviors()), len(s.Store.Incidents()), levels["NORMAL"], levels["WATCH"], levels["INVESTIGATION"])
}
func validateEvent(e model.RuntimeEvent) error {
	missing := []string{}
	if e.EventID == "" {
		missing = append(missing, "event_id")
	}
	if e.Type == "" {
		missing = append(missing, "type")
	}
	if e.Host == "" {
		missing = append(missing, "host")
	}
	if e.PID == 0 {
		missing = append(missing, "pid")
	}
	if e.Process == "" || e.Process == "." {
		missing = append(missing, "process")
	}
	if e.ProcessEntityID == "" {
		missing = append(missing, "process_entity_id")
	}
	if len(missing) > 0 {
		return NewError(400, "Missing event fields: "+strings.Join(missing, ", "))
	}
	return nil
}

type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string                  { return e.Message }
func NewError(status int, message string) error { return &Error{Status: status, Message: message} }
func stringValue(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func detailString(details map[string]any, key string) string {
	value, _ := details[key].(string)
	return value
}

func normalizedSeverity(value string) string {
	switch strings.ToLower(value) {
	case "low", "medium", "high", "critical":
		return strings.ToLower(value)
	default:
		return "high"
	}
}

func firstString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
