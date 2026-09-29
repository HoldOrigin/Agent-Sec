CREATE TABLE IF NOT EXISTS runtime_events (
    event_id TEXT PRIMARY KEY,
    observed_at TIMESTAMPTZ NOT NULL,
    event_type TEXT NOT NULL,
    host_id TEXT NOT NULL,
    container_id TEXT NOT NULL DEFAULT '',
    process_entity_id TEXT NOT NULL DEFAULT '',
    payload JSONB NOT NULL,
    stored_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- migrate:split
CREATE INDEX IF NOT EXISTS idx_runtime_events_observed_at ON runtime_events (observed_at DESC);
-- migrate:split
CREATE INDEX IF NOT EXISTS idx_runtime_events_scope ON runtime_events (host_id, container_id, observed_at DESC);
-- migrate:split
CREATE INDEX IF NOT EXISTS idx_runtime_events_process ON runtime_events (process_entity_id, observed_at DESC);
-- migrate:split
CREATE TABLE IF NOT EXISTS behaviors (
    behavior_id TEXT PRIMARY KEY,
    observed_at TIMESTAMPTZ NOT NULL,
    behavior_type TEXT NOT NULL,
    behavior_code TEXT NOT NULL,
    host_id TEXT NOT NULL DEFAULT '',
    container_id TEXT NOT NULL DEFAULT '',
    correlation_key TEXT NOT NULL DEFAULT '',
    payload JSONB NOT NULL,
    stored_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- migrate:split
CREATE INDEX IF NOT EXISTS idx_behaviors_scope ON behaviors (host_id, container_id, observed_at DESC);
-- migrate:split
CREATE INDEX IF NOT EXISTS idx_behaviors_correlation ON behaviors (correlation_key, observed_at DESC);
-- migrate:split
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'server',
    host_id TEXT NOT NULL DEFAULT '',
    container_id TEXT NOT NULL DEFAULT '',
    correlation_key TEXT NOT NULL DEFAULT '',
    payload JSONB NOT NULL,
    stored_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- migrate:split
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'server';
-- migrate:split
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS host_id TEXT NOT NULL DEFAULT '';
-- migrate:split
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS container_id TEXT NOT NULL DEFAULT '';
-- migrate:split
CREATE INDEX IF NOT EXISTS idx_alerts_updated ON alerts (updated_at DESC);
-- migrate:split
CREATE INDEX IF NOT EXISTS idx_alerts_status_severity ON alerts (status, severity, updated_at DESC);
-- migrate:split
CREATE INDEX IF NOT EXISTS idx_alerts_correlation ON alerts (correlation_key, status);
-- migrate:split
CREATE INDEX IF NOT EXISTS idx_alerts_scope ON alerts (host_id, container_id, updated_at DESC);
-- migrate:split
CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts (source, updated_at DESC);
-- migrate:split
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    start_time TIMESTAMPTZ NOT NULL,
    end_time TIMESTAMPTZ NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    host_id TEXT NOT NULL DEFAULT '',
    container_id TEXT NOT NULL DEFAULT '',
    payload JSONB NOT NULL,
    stored_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
-- migrate:split
CREATE INDEX IF NOT EXISTS idx_incidents_updated ON incidents (updated_at DESC);
-- migrate:split
CREATE INDEX IF NOT EXISTS idx_incidents_scope ON incidents (host_id, container_id, start_time DESC);
-- migrate:split
CREATE INDEX IF NOT EXISTS idx_incidents_status_severity ON incidents (status, severity, updated_at DESC);
