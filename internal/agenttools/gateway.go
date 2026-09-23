package tools

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"sentinel/internal/agentdomain"
)

type CursorCodec struct {
	key []byte
	ttl time.Duration
}

type cursorPayload struct {
	RunID       string    `json:"run_id"`
	TaskID      string    `json:"task_id"`
	ScopeID     string    `json:"scope_id"`
	SnapshotID  string    `json:"snapshot_id"`
	Tool        string    `json:"tool"`
	Fingerprint string    `json:"fingerprint"`
	Offset      int       `json:"offset"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func NewCursorCodec(key []byte, ttl time.Duration) (*CursorCodec, error) {
	if len(key) < 32 || ttl <= 0 {
		return nil, fmt.Errorf("cursor key must be at least 32 bytes and ttl must be positive")
	}
	return &CursorCodec{key: append([]byte(nil), key...), ttl: ttl}, nil
}

func (c *CursorCodec) Encode(payload cursorPayload) (string, error) {
	payload.ExpiresAt = time.Now().UTC().Add(c.ttl)
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, c.key)
	_, _ = mac.Write(raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (c *CursorCodec) Decode(token string) (cursorPayload, *ToolError) {
	var payload cursorPayload
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return payload, reject(ErrInvalidCursor, "cursor", "游标格式不合法", false)
	}
	raw, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	sig, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	if err1 != nil || err2 != nil {
		return payload, reject(ErrInvalidCursor, "cursor", "游标格式不合法", false)
	}
	mac := hmac.New(sha256.New, c.key)
	_, _ = mac.Write(raw)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return payload, reject(ErrInvalidCursor, "cursor", "游标签名不合法", false)
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return payload, reject(ErrInvalidCursor, "cursor", "游标内容不合法", false)
	}
	if time.Now().UTC().After(payload.ExpiresAt) {
		return payload, reject(ErrCursorExpired, "cursor", "游标已过期", false)
	}
	return payload, nil
}

type Gateway struct {
	registry *Registry
	adapters map[string]Adapter
	cursors  *CursorCodec
	auditor  Auditor
	mu       sync.RWMutex
	cache    map[string]Result
}

func NewGateway(registry *Registry, adapters map[string]Adapter, cursorKey []byte, auditor Auditor) (*Gateway, error) {
	codec, err := NewCursorCodec(cursorKey, 15*time.Minute)
	if err != nil {
		return nil, err
	}
	if auditor == nil {
		auditor = NopAuditor{}
	}
	return &Gateway{registry: registry, adapters: adapters, cursors: codec, auditor: auditor, cache: map[string]Result{}}, nil
}

func (g *Gateway) Invoke(ctx context.Context, request Request, invocation InvocationContext) Result {
	fail := func(status Status, toolErr *ToolError) Result {
		result := Result{Status: status, Tool: request.Tool, Error: toolErr,
			Coverage: Coverage{QueryComplete: false, TelemetryState: "UNKNOWN", Warnings: []string{}}}
		_ = g.audit(ctx, "TOOL_END", request, result)
		return result
	}
	if request.CallID == "" || len(request.CallID) > 128 {
		return fail(StatusRejected, reject(ErrInvalidArguments, "call_id", "调用ID不合法", false))
	}
	spec, ok := g.registry.Get(request.Tool)
	if !ok {
		return fail(StatusRejected, reject(ErrUnknownTool, "tool", "工具不存在", false))
	}
	if _, ok := invocation.AllowedTools[request.Tool]; !ok {
		return fail(StatusDenied, reject(ErrToolNotAllowed, "tool", "工具不在任务白名单", false))
	}
	if _, ok := invocation.ActiveTools[request.Tool]; !ok {
		return fail(StatusRejected, reject(ErrToolNotActive, "tool", "工具前置条件尚未满足", true))
	}
	args, toolErr := validateArguments(spec, request.Arguments, invocation)
	if toolErr != nil {
		return fail(statusFor(toolErr), toolErr)
	}
	fingerprint := hashJSON([]any{invocation.RunID, invocation.TaskID, invocation.Scope.ID,
		invocation.Scope.SnapshotID, request.Tool, args})
	offset := 0
	if value, exists := args["cursor"]; exists && value != nil {
		payload, cursorErr := g.cursors.Decode(value.(string))
		if cursorErr != nil {
			return fail(StatusRejected, cursorErr)
		}
		if payload.RunID != invocation.RunID || payload.TaskID != invocation.TaskID ||
			payload.ScopeID != invocation.Scope.ID || payload.SnapshotID != invocation.Scope.SnapshotID ||
			payload.Tool != request.Tool || payload.Fingerprint != fingerprintWithoutCursor(invocation, request.Tool, args) {
			return fail(StatusRejected, reject(ErrInvalidCursor, "cursor", "游标不属于当前查询", false))
		}
		offset = payload.Offset
	}
	cacheKey := hashJSON([]any{fingerprint, offset})
	g.mu.RLock()
	cached, found := g.cache[cacheKey]
	g.mu.RUnlock()
	if found {
		cached.Cached = true
		if err := g.audit(ctx, "TOOL_CACHE_HIT", request, cached); err != nil {
			return Result{Status: StatusError, Tool: request.Tool, Error: err,
				Coverage: Coverage{QueryComplete: false, TelemetryState: "UNKNOWN", Warnings: []string{}}}
		}
		return cached
	}
	adapter, ok := g.adapters[spec.Source]
	if !ok {
		return fail(StatusUnsupported, reject(ErrSourceUnavailable, "", "数据源未配置", false))
	}
	if err := g.audit(ctx, "TOOL_START", request, Result{Status: "RUNNING", Tool: request.Tool}); err != nil {
		return Result{Status: StatusError, Tool: request.Tool, Error: err,
			Coverage: Coverage{QueryComplete: false, TelemetryState: "UNKNOWN", Warnings: []string{}}}
	}
	if invocation.Budget != nil {
		if budgetErr := invocation.Budget.ReserveToolCall(); budgetErr != nil {
			return fail(StatusLimit, budgetErr)
		}
	}
	adapterResult, adapterErr := adapter.Query(ctx, spec, withOffset(args, offset), invocation)
	if adapterErr != nil {
		return fail(statusFor(adapterErr), adapterErr)
	}
	result, resultErr := g.validateResult(request.Tool, spec, adapterResult, invocation, args)
	if resultErr != nil {
		return fail(statusFor(resultErr), resultErr)
	}
	if adapterResult.HasMore {
		cursor, err := g.cursors.Encode(cursorPayload{RunID: invocation.RunID, TaskID: invocation.TaskID,
			ScopeID: invocation.Scope.ID, SnapshotID: invocation.Scope.SnapshotID, Tool: request.Tool,
			Fingerprint: fingerprintWithoutCursor(invocation, request.Tool, args), Offset: adapterResult.NextOffset})
		if err != nil {
			return fail(StatusError, reject(ErrResultSchemaInvalid, "", "无法生成分页游标", false))
		}
		result.NextCursor = cursor
	}
	g.mu.Lock()
	g.cache[cacheKey] = result
	g.mu.Unlock()
	if err := g.audit(ctx, "TOOL_END", request, result); err != nil {
		return Result{Status: StatusError, Tool: request.Tool, Error: err,
			Coverage: Coverage{QueryComplete: false, TelemetryState: "UNKNOWN", Warnings: []string{}}}
	}
	return result
}

func validateArguments(spec Spec, raw map[string]any, invocation InvocationContext) (map[string]any, *ToolError) {
	if raw == nil {
		return nil, reject(ErrInvalidArguments, "arguments", "参数必须是对象", true)
	}
	for name := range raw {
		if _, ok := spec.Fields[name]; !ok {
			return nil, reject(ErrInvalidArguments, name, "包含未声明字段", true)
		}
	}
	result := make(map[string]any, len(raw))
	for name, field := range spec.Fields {
		value, exists := raw[name]
		if !exists {
			if field.Required {
				return nil, reject(ErrInvalidArguments, name, "缺少必需字段", true)
			}
			continue
		}
		if value == nil {
			if field.Nullable {
				result[name] = nil
				continue
			}
			return nil, reject(ErrInvalidArguments, name, "字段不能为空", true)
		}
		switch field.Kind {
		case FieldString:
			text, ok := value.(string)
			if !ok || strings.TrimSpace(text) == "" || (field.MaxLength > 0 && len(text) > field.MaxLength) {
				return nil, reject(ErrInvalidArguments, name, "字符串参数不合法", true)
			}
			if len(field.Enum) > 0 && !contains(field.Enum, text) {
				return nil, reject(ErrInvalidArguments, name, "枚举值不合法", true)
			}
			if len(field.EntityTypes) > 0 && text == "scope" {
				if name != "entity_ref" || !spec.AllowScopeRoot {
					return nil, reject(ErrEntityTypeMismatch, name, "该字段不接受Scope根实体", true)
				}
			} else if len(field.EntityTypes) > 0 {
				entity, ok := invocation.Entities.Resolve(text)
				if !ok {
					return nil, reject(ErrUnknownEntity, name, "实体未登记", true)
				}
				if entity.TenantID != invocation.Scope.TenantID || entity.ScopeID != invocation.Scope.ID || entity.SnapshotID != invocation.Scope.SnapshotID {
					return nil, reject(ErrScopeViolation, name, "实体不属于当前Scope", false)
				}
				if !containsEntity(field.EntityTypes, entity.Type) {
					return nil, reject(ErrEntityTypeMismatch, name, "实体类型不符合工具要求", true)
				}
			}
			result[name] = text
		case FieldStringArray:
			values, ok := stringSlice(value)
			if !ok || len(values) == 0 || (field.MaxLength > 0 && len(values) > field.MaxLength) {
				return nil, reject(ErrInvalidArguments, name, "字符串数组参数不合法", true)
			}
			seen := map[string]struct{}{}
			for _, item := range values {
				if _, duplicate := seen[item]; duplicate || (len(field.Enum) > 0 && !contains(field.Enum, item)) {
					return nil, reject(ErrInvalidArguments, name, "数组包含重复或未知值", true)
				}
				seen[item] = struct{}{}
			}
			result[name] = values
		case FieldInteger:
			number, ok := exactInt(value)
			if !ok || number < field.MinInt || number > field.MaxInt {
				return nil, reject(ErrInvalidArguments, name, "整数参数超出范围", true)
			}
			result[name] = number
		default:
			return nil, reject(ErrInvalidArguments, name, "字段类型未配置", false)
		}
	}
	if relation, ok := result["relation"].(string); ok {
		ref, _ := result["entity_ref"].(string)
		if (ref == "scope") != (relation == "tree") {
			return nil, reject(ErrRelationNotAllowed, "relation", "Scope根实体只能使用tree关系", true)
		}
		if ref == "scope" && !spec.AllowScopeRoot {
			return nil, reject(ErrRelationNotAllowed, "entity_ref", "工具不允许Scope根查询", true)
		}
	}
	return result, nil
}

func (g *Gateway) validateResult(tool string, spec Spec, raw AdapterResult, invocation InvocationContext, args map[string]any) (Result, *ToolError) {
	if raw.Status == "" {
		raw.Status = StatusOK
	}
	if raw.Status != StatusOK && raw.Status != StatusEmpty && raw.Status != StatusPartial && raw.Status != StatusNotApplicable {
		return Result{}, reject(ErrResultSchemaInvalid, "status", "适配器返回未知状态", false)
	}
	queryID := randomID("q-")
	result := Result{Status: raw.Status, QueryID: queryID, Tool: tool, EntityRefs: raw.EntityRefs, Data: raw.Data,
		Coverage: raw.Coverage, Evidence: []domain.Evidence{}, EvidenceRefs: []string{}}
	encodedData, dataErr := json.Marshal(raw.Data)
	if dataErr != nil || len(encodedData) > 64*1024 {
		return Result{}, reject(ErrResultSchemaInvalid, "data", "工具结构化结果不合法或过大", false)
	}
	if len(raw.Events) == 0 && len(raw.Data) == 0 && raw.Status == StatusOK {
		result.Status = StatusEmpty
	}
	allowedKinds := map[domain.EventKind]struct{}{}
	if requested, ok := args["event_types"].([]string); ok {
		for _, kind := range requested {
			allowedKinds[domain.EventKind(kind)] = struct{}{}
		}
	} else {
		for _, kind := range spec.EventKinds {
			allowedKinds[kind] = struct{}{}
		}
	}
	for _, event := range raw.Events {
		if err := event.Validate(); err != nil {
			return Result{}, reject(ErrResultSchemaInvalid, "events", "事件结构不合法", false)
		}
		if !invocation.Scope.Contains(event) {
			return Result{}, reject(ErrResultScopeViolation, "events", "工具返回Scope外事件", false)
		}
		if _, ok := allowedKinds[event.Kind]; !ok {
			return Result{}, reject(ErrResultTampered, "events", "工具返回未请求事件类型", false)
		}
		sourceEvent, _ := json.Marshal(event)
		projected := redactEvent(event)
		rawEvent, _ := json.Marshal(projected)
		evidence := domain.Evidence{ID: randomID("ev-"), RunID: invocation.RunID, QueryID: queryID,
			Source: raw.Coverage.Source, SourceEventID: event.ID, ObservedAt: event.ObservedAt,
			SubjectRefs: nonEmpty(event.IdentityID, event.SessionID, event.ProcessID),
			ObjectRefs:  nonEmpty(event.HostID, event.ContainerID), Fact: fact(event),
			SourceHash: hashBytes(sourceEvent), Event: rawEvent}
		result.Evidence = append(result.Evidence, evidence)
		result.EvidenceRefs = append(result.EvidenceRefs, evidence.ID)
	}
	return result, nil
}

func redactEvent(event domain.Event) domain.Event {
	if len(event.Details) == 0 {
		return event
	}
	var details any
	if json.Unmarshal(event.Details, &details) != nil {
		event.Details = json.RawMessage(`{"redaction":"INVALID_DETAILS"}`)
		return event
	}
	event.Details, _ = json.Marshal(redactValue(details))
	return event
}

func redactValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			lower := strings.ToLower(key)
			if strings.Contains(lower, "password") || strings.Contains(lower, "passwd") || strings.Contains(lower, "secret") ||
				strings.Contains(lower, "token") || strings.Contains(lower, "cookie") || strings.Contains(lower, "authorization") ||
				strings.Contains(lower, "credential") || strings.Contains(lower, "request_body") {
				out[key] = "[REDACTED]"
			} else {
				out[key] = redactValue(item)
			}
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i := range typed {
			out[i] = redactValue(typed[i])
		}
		return out
	case string:
		if len(typed) > 2000 {
			return typed[:2000] + "...[TRUNCATED]"
		}
		return typed
	default:
		return value
	}
}

func (g *Gateway) audit(ctx context.Context, event string, request Request, result Result) *ToolError {
	details, _ := json.Marshal(map[string]any{"arguments": request.Arguments, "result": result})
	if err := g.auditor.Write(ctx, AuditRecord{Event: event, CallID: request.CallID, Tool: request.Tool, Status: result.Status, Details: details}); err != nil {
		return reject(ErrPersistenceFailure, "", "工具审计写入失败", false)
	}
	return nil
}

func reject(code ErrorCode, field, message string, retryable bool) *ToolError {
	return &ToolError{Code: code, Field: field, SafeMessage: message, Retryable: retryable}
}
func statusFor(err *ToolError) Status {
	if err.Code == ErrToolNotAllowed || err.Code == ErrScopeViolation {
		return StatusDenied
	}
	if err.Code == ErrSourceUnavailable {
		return StatusUnsupported
	}
	if err.Code == ErrBudgetExceeded {
		return StatusLimit
	}
	return StatusRejected
}
func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
func containsEntity(values []domain.EntityType, target domain.EntityType) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
func stringSlice(value any) ([]string, bool) {
	raw, ok := value.([]string)
	if ok {
		return raw, true
	}
	generic, ok := value.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, len(generic))
	for i, item := range generic {
		text, ok := item.(string)
		if !ok || text == "" {
			return nil, false
		}
		out[i] = text
	}
	return out, true
}
func exactInt(value any) (int64, bool) {
	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int64:
		return typed, true
	case json.Number:
		number, err := typed.Int64()
		return number, err == nil
	default:
		return 0, false
	}
}
func hashJSON(value any) string     { raw, _ := json.Marshal(value); return hashBytes(raw) }
func hashBytes(value []byte) string { sum := sha256.Sum256(value); return hex.EncodeToString(sum[:]) }
func fingerprintWithoutCursor(inv InvocationContext, tool string, args map[string]any) string {
	clone := map[string]any{}
	for key, value := range args {
		if key != "cursor" {
			clone[key] = value
		}
	}
	return hashJSON([]any{inv.RunID, inv.TaskID, inv.Scope.ID, inv.Scope.SnapshotID, tool, clone})
}
func withOffset(args map[string]any, offset int) map[string]any {
	out := map[string]any{}
	for key, value := range args {
		out[key] = value
	}
	out["_offset"] = offset
	return out
}
func randomID(prefix string) string {
	raw := make([]byte, 12)
	_, _ = rand.Read(raw)
	return prefix + hex.EncodeToString(raw)
}
func nonEmpty(values ...string) []string {
	out := []string{}
	for _, value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}
func fact(event domain.Event) string {
	return fmt.Sprintf("%s在%s产生%s，结果%s", event.ProcessID, event.ObservedAt.UTC().Format(time.RFC3339Nano), event.Kind, event.Outcome)
}

type MemoryEntities struct {
	mu     sync.RWMutex
	values map[string]domain.Entity
}

func NewMemoryEntities(values ...domain.Entity) *MemoryEntities {
	store := &MemoryEntities{values: map[string]domain.Entity{}}
	for _, value := range values {
		store.values[value.ID] = value
	}
	return store
}
func (m *MemoryEntities) Resolve(id string) (domain.Entity, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	value, ok := m.values[id]
	return value, ok
}
func (m *MemoryEntities) Put(value domain.Entity) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.values[value.ID] = value
}

func (m *MemoryEntities) List() []domain.Entity {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]domain.Entity, 0, len(m.values))
	for _, value := range m.values {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

type CounterBudget struct {
	mu          sync.Mutex
	Used, Limit int
}

func (b *CounterBudget) ReserveToolCall() *ToolError {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.Used >= b.Limit {
		return reject(ErrBudgetExceeded, "", "工具调用额度耗尽", false)
	}
	b.Used++
	return nil
}
