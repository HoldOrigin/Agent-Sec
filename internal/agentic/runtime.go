package investigation

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	agentaudit "sentinel/internal/agentaudit"
	agentdomain "sentinel/internal/agentdomain"
	agentllm "sentinel/internal/agentllm"
	agenttools "sentinel/internal/agenttools"
	"sentinel/internal/model"
	"sentinel/internal/store"
)

// RuntimeConfig keeps model roles and execution budgets independent. The three
// roles may use different Qwen models; all default to qwen3.7-plus.
type RuntimeConfig struct {
	APIKey        string
	PlannerModel  string
	ExecutorModel string
	AnalyzerModel string
	AuditPath     string
	MaxDecisions  int
	MaxToolCalls  int
	Window        time.Duration
}

// Runtime adapts Agent-Sec's existing event store to the guarded agent tool
// gateway. It deliberately exposes only read-only investigation tools.
type Runtime struct {
	store     *store.Memory
	roles     Roles
	registry  *agenttools.Registry
	logger    *agentaudit.Logger
	cursorKey []byte
	config    RuntimeConfig
}

func NewRuntime(eventStore *store.Memory, config RuntimeConfig) (*Runtime, error) {
	if eventStore == nil {
		return nil, fmt.Errorf("event store is required")
	}
	qwen, err := agentllm.NewQwen(config.APIKey)
	if err != nil {
		return nil, err
	}
	registry, err := agenttools.NewRegistry(agenttools.DefaultSpecs())
	if err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("create cursor signing key: %w", err)
	}
	if config.MaxDecisions <= 0 {
		config.MaxDecisions = 4
	}
	if config.MaxToolCalls <= 0 {
		config.MaxToolCalls = 12
	}
	if config.Window <= 0 {
		config.Window = 5 * time.Minute
	}
	caller := agentllm.RetryingCaller{Next: qwen, MaxAttempts: 3, BaseDelay: 250 * time.Millisecond}
	return &Runtime{
		store:     eventStore,
		roles:     NewQwenRoles(caller, config.PlannerModel, config.ExecutorModel, config.AnalyzerModel),
		registry:  registry,
		logger:    &agentaudit.Logger{Terminal: slog.Default(), Path: config.AuditPath},
		cursorKey: key,
		config:    config,
	}, nil
}

func (r *Runtime) Models() map[string]string { return r.roles.Identities() }

func (r *Runtime) Investigate(ctx context.Context, incident model.Incident) (RunResult, error) {
	if incident.IncidentID == "" {
		return RunResult{}, fmt.Errorf("incident id is required")
	}
	domainEvents, entities, scope := r.snapshot(incident)
	repository := agenttools.NewMemoryEvents(domainEvents...)
	gateway, err := agenttools.NewGateway(r.registry, map[string]agenttools.Adapter{
		"events":    agenttools.EventAdapter{Repository: repository},
		"telemetry": agenttools.TelemetryAdapter{},
	}, r.cursorKey, r.logger)
	if err != nil {
		return RunResult{}, err
	}
	available := map[string]struct{}{
		"process_events_query":         {},
		"file_events_query":            {},
		"network_connections_query":    {},
		"dns_events_query":             {},
		"privilege_events_query":       {},
		"kernel_security_events_query": {},
		"telemetry_health_get":         {},
	}
	controller := Controller{
		Roles: r.roles, Registry: r.registry, Gateway: gateway, Logger: r.logger,
		MaxDecisions: r.config.MaxDecisions, MaxToolCalls: r.config.MaxToolCalls,
	}
	alertID := incident.AlertID
	if alertID == "" {
		alertID = "incident:" + incident.IncidentID
	}
	return controller.Run(ctx, RunRequest{
		Alert: agentdomain.Alert{ID: alertID, TenantID: "default", Severity: incident.Severity,
			Title: incident.Title, SeedEventID: first(incident.EvidenceEventIDs), CreatedAt: incident.CreatedAt},
		Scope: scope, AvailableTools: available, Entities: entities,
	})
}

func (r *Runtime) snapshot(incident model.Incident) ([]agentdomain.Event, *agenttools.MemoryEntities, agentdomain.Scope) {
	start := incident.StartTime
	end := incident.EndTime
	if start.IsZero() {
		start = time.Now().UTC()
	}
	if end.IsZero() || end.Before(start) {
		end = start
	}
	scope := agentdomain.Scope{
		ID: incident.IncidentID, TenantID: "default",
		Start: start.Add(-r.config.Window), End: end.Add(r.config.Window),
		SnapshotID: fmt.Sprintf("%s-%d", incident.IncidentID, time.Now().UTC().UnixNano()),
	}
	if incident.HostID != "" {
		scope.AllowedHosts = []string{incident.HostID}
	}
	if incident.ContainerID != "" {
		scope.AllowedWorkloads = []string{incident.ContainerID}
	}
	entities := []agentdomain.Entity{}
	put := func(id string, kind agentdomain.EntityType, attributes map[string]any) {
		if id == "" {
			return
		}
		raw, _ := json.Marshal(attributes)
		entities = append(entities, agentdomain.Entity{ID: id, Type: kind, TenantID: scope.TenantID,
			ScopeID: scope.ID, SnapshotID: scope.SnapshotID, Attributes: raw})
	}
	put(incident.AlertID, agentdomain.EntityAlert, nil)
	put(incident.HostID, agentdomain.EntityHost, nil)
	put(incident.ContainerID, agentdomain.EntityContainer, map[string]any{"workload": incident.Workload, "namespace": incident.Namespace})
	events := make([]agentdomain.Event, 0)
	for _, event := range r.store.Events() {
		converted := convertEvent(event)
		if !scope.Contains(converted) {
			continue
		}
		events = append(events, converted)
		put(event.ProcessEntityID, agentdomain.EntityProcess, map[string]any{"parent_process_id": event.ParentProcessEntityID, "pid": event.PID, "exe": event.Exe})
	}
	return events, agenttools.NewMemoryEntities(entities...), scope
}

func convertEvent(event model.RuntimeEvent) agentdomain.Event {
	kind := strings.ToUpper(event.EventType)
	if kind == "" {
		kind = strings.ToUpper(event.Type)
	}
	details, _ := json.Marshal(map[string]any{
		"process": event.Process, "exe": event.Exe, "argv": event.Argv, "cmdline": event.Cmdline,
		"uid": event.UID, "pod": event.Pod, "namespace": event.Namespace, "workload": event.Workload,
		"metadata": event.Metadata,
	})
	bootID := event.BootID
	if bootID == "" {
		bootID = "unknown"
	}
	hostID := event.HostID
	if hostID == "" {
		hostID = event.Host
	}
	observed := event.Timestamp
	if observed.IsZero() {
		observed = time.Now().UTC()
	}
	return agentdomain.Event{
		ID: event.EventID, SchemaVersion: 1, TenantID: "default", SensorID: hostID,
		HostID: hostID, BootID: bootID, ContainerID: event.ContainerID,
		ProcessID: event.ProcessEntityID, ParentProcess: event.ParentProcessEntityID,
		Kind: agentdomain.EventKind(kind), Outcome: agentdomain.OutcomeUnknown,
		ObservedAt: observed, IngestedAt: observed, Details: details,
	}
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
