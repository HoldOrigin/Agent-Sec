package store

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"sentinel/internal/model"
)

//go:embed schema.sql
var postgresSchema string

type PostgresOptions struct {
	MaxOpenConnections int
	MaxIdleConnections int
	OperationTimeout   time.Duration
}

// Postgres is a durable write-through repository. PostgreSQL is the source of
// truth; an in-process cache keeps the existing MVP query and correlation path
// fast. The cache is rebuilt from JSONB payloads at startup.
type Postgres struct {
	db      *sql.DB
	cache   *Memory
	timeout time.Duration
	mu      sync.Mutex
}

func NewPostgres(ctx context.Context, databaseURL string, options PostgresOptions) (*Postgres, error) {
	if strings.TrimSpace(databaseURL) == "" {
		return nil, fmt.Errorf("database URL is required")
	}
	if options.MaxOpenConnections <= 0 {
		options.MaxOpenConnections = 10
	}
	if options.MaxIdleConnections < 0 {
		options.MaxIdleConnections = 0
	}
	if options.MaxIdleConnections == 0 {
		options.MaxIdleConnections = 5
	}
	if options.OperationTimeout <= 0 {
		options.OperationTimeout = 5 * time.Second
	}
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("open PostgreSQL: %w", err)
	}
	db.SetMaxOpenConns(options.MaxOpenConnections)
	db.SetMaxIdleConns(options.MaxIdleConnections)
	db.SetConnMaxIdleTime(5 * time.Minute)
	store := &Postgres{db: db, cache: NewMemory(), timeout: options.OperationTimeout}
	if err := store.initialize(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Postgres) initialize(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, s.timeout)
	defer cancel()
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("connect PostgreSQL: %w", err)
	}
	for _, statement := range strings.Split(postgresSchema, "-- migrate:split") {
		statement = strings.TrimSpace(statement)
		if statement == "" {
			continue
		}
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("migrate PostgreSQL schema: %w", err)
		}
	}
	if err := s.load(ctx); err != nil {
		return fmt.Errorf("load PostgreSQL snapshot: %w", err)
	}
	return nil
}

func (s *Postgres) load(ctx context.Context) error {
	if err := loadJSONRows(ctx, s.db, "SELECT payload FROM runtime_events", func(data []byte) error {
		var item model.RuntimeEvent
		if err := json.Unmarshal(data, &item); err != nil {
			return err
		}
		s.cache.events[item.EventID] = item
		return nil
	}); err != nil {
		return fmt.Errorf("events: %w", err)
	}
	if err := loadJSONRows(ctx, s.db, "SELECT payload FROM behaviors", func(data []byte) error {
		var item model.Behavior
		if err := json.Unmarshal(data, &item); err != nil {
			return err
		}
		s.cache.behaviors[item.BehaviorID] = item
		return nil
	}); err != nil {
		return fmt.Errorf("behaviors: %w", err)
	}
	if err := loadJSONRows(ctx, s.db, "SELECT payload FROM alerts", func(data []byte) error {
		var item model.Alert
		if err := json.Unmarshal(data, &item); err != nil {
			return err
		}
		if item.Source == "" {
			item.Source = "server"
		}
		s.cache.alerts[item.AlertID] = item
		return nil
	}); err != nil {
		return fmt.Errorf("alerts: %w", err)
	}
	if err := loadJSONRows(ctx, s.db, "SELECT payload FROM incidents", func(data []byte) error {
		var item model.Incident
		if err := json.Unmarshal(data, &item); err != nil {
			return err
		}
		s.cache.incidents[item.IncidentID] = item
		return nil
	}); err != nil {
		return fmt.Errorf("incidents: %w", err)
	}
	return nil
}

func loadJSONRows(ctx context.Context, db *sql.DB, query string, accept func([]byte) error) error {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return err
		}
		if err := accept(payload); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (s *Postgres) Reset() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	if _, err := s.db.ExecContext(ctx, "TRUNCATE TABLE incidents, alerts, behaviors, runtime_events"); err != nil {
		return fmt.Errorf("truncate repository: %w", err)
	}
	s.cache.reset()
	return nil
}

func (s *Postgres) AddEvent(event model.RuntimeEvent) (model.RuntimeEvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	payload, err := json.Marshal(event)
	if err != nil {
		return model.RuntimeEvent{}, fmt.Errorf("marshal event: %w", err)
	}
	eventType := event.EventType
	if eventType == "" {
		eventType = event.Type
	}
	hostID := event.HostID
	if hostID == "" {
		hostID = event.Host
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	_, err = s.db.ExecContext(ctx, `INSERT INTO runtime_events
        (event_id, observed_at, event_type, host_id, container_id, process_entity_id, payload)
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        ON CONFLICT (event_id) DO UPDATE SET observed_at=EXCLUDED.observed_at,
        event_type=EXCLUDED.event_type, host_id=EXCLUDED.host_id,
        container_id=EXCLUDED.container_id, process_entity_id=EXCLUDED.process_entity_id,
        payload=EXCLUDED.payload, stored_at=NOW()`, event.EventID, event.Timestamp, eventType,
		hostID, event.ContainerID, event.ProcessEntityID, string(payload))
	if err != nil {
		return model.RuntimeEvent{}, fmt.Errorf("upsert event: %w", err)
	}
	return s.cache.AddEvent(event)
}

func (s *Postgres) ReplaceBehaviors(items []model.Behavior) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin behavior replacement: %w", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "DELETE FROM behaviors"); err != nil {
		return fmt.Errorf("clear behaviors: %w", err)
	}
	for _, item := range items {
		payload, err := json.Marshal(item)
		if err != nil {
			return fmt.Errorf("marshal behavior %s: %w", item.BehaviorID, err)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO behaviors
            (behavior_id, observed_at, behavior_type, behavior_code, host_id, container_id, correlation_key, payload)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, item.BehaviorID, item.Timestamp, item.Type,
			item.Code, item.Scope.HostID, item.Scope.ContainerID, item.CorrelationKey, string(payload))
		if err != nil {
			return fmt.Errorf("insert behavior %s: %w", item.BehaviorID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit behavior replacement: %w", err)
	}
	return s.cache.ReplaceBehaviors(items)
}

func (s *Postgres) AddAlert(alert model.Alert) (model.Alert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	merged := alert
	s.cache.mu.RLock()
	for _, existing := range s.cache.alerts {
		if existing.CorrelationKey != alert.CorrelationKey || existing.Status == "closed" {
			continue
		}
		merged = existing
		merged.RuleIDs = unique(append(append([]string{}, existing.RuleIDs...), alert.RuleIDs...))
		merged.EventIDs = unique(append(append([]string{}, existing.EventIDs...), alert.EventIDs...))
		if alert.Source == "collector" || existing.Source == "" {
			merged.Source = alert.Source
			merged.Title = firstNonEmpty(alert.Title, existing.Title)
			merged.Description = firstNonEmpty(alert.Description, existing.Description)
			merged.HostID = firstNonEmpty(alert.HostID, existing.HostID)
			merged.ContainerID = firstNonEmpty(alert.ContainerID, existing.ContainerID)
		}
		if severityRank(alert.Severity) > severityRank(existing.Severity) {
			merged.Severity = alert.Severity
		}
		merged.UpdatedAt = time.Now().UTC()
		break
	}
	s.cache.mu.RUnlock()
	payload, err := json.Marshal(merged)
	if err != nil {
		return model.Alert{}, fmt.Errorf("marshal alert: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	_, err = s.db.ExecContext(ctx, `INSERT INTO alerts
		(alert_id, created_at, updated_at, severity, status, source, host_id, container_id, correlation_key, payload)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (alert_id) DO UPDATE SET updated_at=EXCLUDED.updated_at,
		severity=EXCLUDED.severity, status=EXCLUDED.status, source=EXCLUDED.source,
		host_id=EXCLUDED.host_id, container_id=EXCLUDED.container_id,
		correlation_key=EXCLUDED.correlation_key, payload=EXCLUDED.payload, stored_at=NOW()`,
		merged.AlertID, merged.CreatedAt, merged.UpdatedAt, merged.Severity, merged.Status,
		merged.Source, merged.HostID, merged.ContainerID, merged.CorrelationKey, string(payload))
	if err != nil {
		return model.Alert{}, fmt.Errorf("upsert alert: %w", err)
	}
	s.cache.mu.Lock()
	s.cache.alerts[merged.AlertID] = merged
	s.cache.mu.Unlock()
	return merged, nil
}

func (s *Postgres) AddIncident(incident model.Incident) (model.Incident, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache.mu.RLock()
	if prior, ok := s.cache.incidents[incident.IncidentID]; ok {
		incident.CreatedAt = prior.CreatedAt
	}
	s.cache.mu.RUnlock()
	if incident.CreatedAt.IsZero() {
		incident.CreatedAt = time.Now().UTC()
	}
	incident.UpdatedAt = time.Now().UTC()
	payload, err := json.Marshal(incident)
	if err != nil {
		return model.Incident{}, fmt.Errorf("marshal incident: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()
	_, err = s.db.ExecContext(ctx, `INSERT INTO incidents
        (incident_id, alert_id, created_at, updated_at, start_time, end_time, severity, status, host_id, container_id, payload)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
        ON CONFLICT (incident_id) DO UPDATE SET alert_id=EXCLUDED.alert_id,
        updated_at=EXCLUDED.updated_at, start_time=EXCLUDED.start_time,
        end_time=EXCLUDED.end_time, severity=EXCLUDED.severity, status=EXCLUDED.status,
        host_id=EXCLUDED.host_id, container_id=EXCLUDED.container_id,
        payload=EXCLUDED.payload, stored_at=NOW()`, incident.IncidentID, incident.AlertID,
		incident.CreatedAt, incident.UpdatedAt, incident.StartTime, incident.EndTime,
		incident.Severity, incident.Status, incident.HostID, incident.ContainerID, string(payload))
	if err != nil {
		return model.Incident{}, fmt.Errorf("upsert incident: %w", err)
	}
	s.cache.mu.Lock()
	s.cache.incidents[incident.IncidentID] = incident
	s.cache.mu.Unlock()
	return incident, nil
}

func (s *Postgres) Events() []model.RuntimeEvent               { return s.cache.Events() }
func (s *Postgres) Event(id string) (model.RuntimeEvent, bool) { return s.cache.Event(id) }
func (s *Postgres) Behaviors() []model.Behavior                { return s.cache.Behaviors() }
func (s *Postgres) Alerts() []model.Alert                      { return s.cache.Alerts() }
func (s *Postgres) Alert(id string) (model.Alert, bool)        { return s.cache.Alert(id) }
func (s *Postgres) Incident(id string) (model.Incident, bool)  { return s.cache.Incident(id) }
func (s *Postgres) Incidents() []model.Incident                { return s.cache.Incidents() }
func (s *Postgres) RelatedEvents(seed model.RuntimeEvent, window time.Duration) []model.RuntimeEvent {
	return s.cache.RelatedEvents(seed, window)
}
func (s *Postgres) Close() error { return s.db.Close() }
func (s *Postgres) Name() string { return "postgresql" }

var _ Repository = (*Postgres)(nil)
var _ Repository = (*Memory)(nil)
