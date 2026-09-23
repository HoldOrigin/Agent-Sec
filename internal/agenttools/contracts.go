package tools

import (
	"context"
	"encoding/json"
	"time"

	"sentinel/internal/agentdomain"
)

type Status string

const (
	StatusOK            Status = "OK"
	StatusEmpty         Status = "EMPTY"
	StatusPartial       Status = "PARTIAL"
	StatusUnsupported   Status = "UNSUPPORTED"
	StatusNotApplicable Status = "NOT_APPLICABLE"
	StatusDenied        Status = "DENIED"
	StatusRejected      Status = "REJECTED"
	StatusLimit         Status = "LIMIT"
	StatusError         Status = "ERROR"
)

type ErrorCode string

const (
	ErrUnknownTool          ErrorCode = "UNKNOWN_TOOL"
	ErrToolNotAllowed       ErrorCode = "TOOL_NOT_ALLOWED"
	ErrToolNotActive        ErrorCode = "TOOL_NOT_ACTIVE"
	ErrInvalidArguments     ErrorCode = "INVALID_ARGUMENTS"
	ErrUnknownEntity        ErrorCode = "UNKNOWN_ENTITY"
	ErrEntityTypeMismatch   ErrorCode = "ENTITY_TYPE_MISMATCH"
	ErrScopeViolation       ErrorCode = "SCOPE_VIOLATION"
	ErrRelationNotAllowed   ErrorCode = "RELATION_NOT_ALLOWED"
	ErrInvalidCursor        ErrorCode = "INVALID_CURSOR"
	ErrCursorExpired        ErrorCode = "CURSOR_EXPIRED"
	ErrSourceUnavailable    ErrorCode = "SOURCE_UNAVAILABLE"
	ErrBudgetExceeded       ErrorCode = "BUDGET_EXCEEDED"
	ErrResultSchemaInvalid  ErrorCode = "RESULT_SCHEMA_INVALID"
	ErrResultScopeViolation ErrorCode = "RESULT_SCOPE_VIOLATION"
	ErrResultTampered       ErrorCode = "RESULT_TAMPERED"
	ErrPersistenceFailure   ErrorCode = "PERSISTENCE_FAILURE"
)

type ToolError struct {
	Code         ErrorCode `json:"code"`
	Field        string    `json:"field,omitempty"`
	SafeMessage  string    `json:"safe_message"`
	Retryable    bool      `json:"retryable"`
	RetryAfterMS int       `json:"retry_after_ms,omitempty"`
}

func (e *ToolError) Error() string { return string(e.Code) }

type Coverage struct {
	QueryComplete  bool      `json:"query_complete"`
	Truncated      bool      `json:"truncated"`
	TelemetryState string    `json:"telemetry_status"`
	Source         string    `json:"source"`
	CoveredStart   time.Time `json:"covered_start,omitempty"`
	CoveredEnd     time.Time `json:"covered_end,omitempty"`
	Warnings       []string  `json:"warnings"`
}

type Request struct {
	CallID    string         `json:"call_id"`
	Tool      string         `json:"tool"`
	Arguments map[string]any `json:"arguments"`
}

type Result struct {
	Status       Status            `json:"status"`
	QueryID      string            `json:"query_id,omitempty"`
	Tool         string            `json:"tool"`
	Evidence     []domain.Evidence `json:"evidence"`
	EvidenceRefs []string          `json:"evidence_refs"`
	EntityRefs   []string          `json:"entity_refs"`
	NextCursor   string            `json:"next_cursor,omitempty"`
	Coverage     Coverage          `json:"coverage"`
	Error        *ToolError        `json:"error,omitempty"`
	Cached       bool              `json:"cached"`
	Data         map[string]any    `json:"data,omitempty"`
}

type InvocationContext struct {
	RunID        string
	TaskID       string
	Scope        domain.Scope
	AllowedTools map[string]struct{}
	ActiveTools  map[string]struct{}
	Entities     EntityResolver
	Budget       Budget
}

type EntityResolver interface {
	Resolve(id string) (domain.Entity, bool)
}

type Budget interface {
	ReserveToolCall() *ToolError
}

type AdapterResult struct {
	Events     []domain.Event
	EntityRefs []string
	NextOffset int
	HasMore    bool
	Coverage   Coverage
	Status     Status
	Data       map[string]any
}

type Adapter interface {
	Query(ctx context.Context, spec Spec, args map[string]any, invocation InvocationContext) (AdapterResult, *ToolError)
}

type AuditRecord struct {
	Event   string
	CallID  string
	Tool    string
	Status  Status
	Details json.RawMessage
}

type Auditor interface {
	Write(ctx context.Context, record AuditRecord) error
}

type NopAuditor struct{}

func (NopAuditor) Write(context.Context, AuditRecord) error { return nil }
