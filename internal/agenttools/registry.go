package tools

import (
	"fmt"
	"sort"

	"sentinel/internal/agentdomain"
)

type FieldKind string

const (
	FieldString      FieldKind = "string"
	FieldStringArray FieldKind = "string_array"
	FieldInteger     FieldKind = "integer"
)

type FieldSpec struct {
	Kind        FieldKind
	Required    bool
	Nullable    bool
	MaxLength   int
	MinInt      int64
	MaxInt      int64
	Enum        []string
	EntityTypes []domain.EntityType
}

type Spec struct {
	Name           string
	Description    string
	Source         string
	Fields         map[string]FieldSpec
	AllowScopeRoot bool
	EventKinds     []domain.EventKind
}

func (s Spec) PublicSchema() map[string]any {
	properties := make(map[string]any, len(s.Fields))
	required := make([]string, 0, len(s.Fields))
	for name, field := range s.Fields {
		item := map[string]any{"type": string(field.Kind)}
		if field.Nullable {
			item["nullable"] = true
		}
		if field.MaxLength > 0 {
			item["max_length"] = field.MaxLength
		}
		if field.Kind == FieldInteger {
			item["minimum"] = field.MinInt
			item["maximum"] = field.MaxInt
		}
		if len(field.Enum) > 0 {
			item["enum"] = append([]string(nil), field.Enum...)
		}
		if len(field.EntityTypes) > 0 {
			types := make([]string, len(field.EntityTypes))
			for i := range field.EntityTypes {
				types[i] = string(field.EntityTypes[i])
			}
			item["entity_types"] = types
		}
		properties[name] = item
		if field.Required {
			required = append(required, name)
		}
	}
	sort.Strings(required)
	result := map[string]any{"type": "object", "additional_properties": false,
		"required": required, "properties": properties}
	if s.AllowScopeRoot {
		result["scope_root_constraint"] = "entity_ref为scope时，relation必须为tree；否则entity_ref必须使用已登记且类型匹配的实体ID"
	}
	return result
}

type Registry struct{ specs map[string]Spec }

func NewRegistry(specs []Spec) (*Registry, error) {
	result := &Registry{specs: make(map[string]Spec, len(specs))}
	for _, spec := range specs {
		if spec.Name == "" || len(spec.Fields) == 0 {
			return nil, fmt.Errorf("tool name and fields are required")
		}
		if _, exists := result.specs[spec.Name]; exists {
			return nil, fmt.Errorf("duplicate tool %s", spec.Name)
		}
		result.specs[spec.Name] = spec
	}
	return result, nil
}

func (r *Registry) Get(name string) (Spec, bool) { spec, ok := r.specs[name]; return spec, ok }

func (r *Registry) PublicCatalog(allowed map[string]struct{}) map[string]map[string]any {
	result := map[string]map[string]any{}
	for name := range allowed {
		if spec, ok := r.specs[name]; ok {
			result[name] = map[string]any{"description": spec.Description, "source": spec.Source,
				"input_schema": spec.PublicSchema()}
		}
	}
	return result
}

func queryFields(entityTypes []domain.EntityType, relations, eventTypes []string) map[string]FieldSpec {
	return map[string]FieldSpec{
		"entity_ref":  {Kind: FieldString, Required: true, MaxLength: 128, EntityTypes: entityTypes},
		"relation":    {Kind: FieldString, Required: true, MaxLength: 64, Enum: relations},
		"event_types": {Kind: FieldStringArray, Required: true, MaxLength: 32, Enum: eventTypes},
		"limit":       {Kind: FieldInteger, Required: true, MinInt: 1, MaxInt: 50},
		"cursor":      {Kind: FieldString, Required: true, Nullable: true, MaxLength: 1024},
	}
}

func DefaultSpecs() []Spec {
	all := func(values ...domain.EventKind) []domain.EventKind { return values }
	stringsOf := func(values ...domain.EventKind) []string {
		out := make([]string, len(values))
		for i := range values {
			out[i] = string(values[i])
		}
		return out
	}
	query := func(name, description, source string, entities []domain.EntityType, relations []string, kinds ...domain.EventKind) Spec {
		return Spec{Name: name, Description: description, Source: source, AllowScopeRoot: true,
			Fields: queryFields(entities, relations, stringsOf(kinds...)), EventKinds: all(kinds...)}
	}
	get := func(name, description, source, field string, entities ...domain.EntityType) Spec {
		return Spec{Name: name, Description: description, Source: source,
			Fields: map[string]FieldSpec{field: {Kind: FieldString, Required: true, MaxLength: 128, EntityTypes: entities}}}
	}
	return []Spec{
		get("alert_get", "读取一条告警和种子引用", "alerts", "alert_ref", domain.EntityAlert),
		{Name: "telemetry_health_get", Description: "读取当前Scope遥测健康", Source: "telemetry",
			Fields: map[string]FieldSpec{"scope_ref": {Kind: FieldString, Required: true, MaxLength: 128}}},
		get("identity_resolve", "解析规范身份", "identity", "identity_hint_ref", domain.EntityIdentity),
		query("login_sessions_query", "查询登录会话", "auth", []domain.EntityType{domain.EntityIdentity, domain.EntityHost}, []string{"self"}, domain.EventSessionLogin, domain.EventSessionLogout),
		query("authentication_events_query", "查询认证事件", "auth", []domain.EntityType{domain.EntityIdentity, domain.EntitySession, domain.EntityIP}, []string{"self"}, domain.EventLoginSuccess, domain.EventLoginFailure, domain.EventMFAChallenge, domain.EventTokenIssue, domain.EventKeyAuth, domain.EventAccountLock),
		get("source_endpoint_resolve", "按事件时间解析来源端点", "network_inventory", "source_ip_ref", domain.EntityIP),
		get("host_context_get", "读取主机上下文", "inventory", "host_ref", domain.EntityHost),
		get("container_context_get", "读取容器上下文", "runtime", "container_ref", domain.EntityContainer),
		get("k8s_workload_context_get", "读取Kubernetes工作负载上下文", "kubernetes", "workload_ref", domain.EntityWorkload, domain.EntityContainer),
		query("process_events_query", "查询进程生命周期", "events", []domain.EntityType{domain.EntityProcess, domain.EntitySession}, []string{"self", "parents", "children", "session_members", "tree"}, domain.EventProcessFork, domain.EventProcessExec, domain.EventProcessExit),
		query("file_events_query", "查询文件状态变化", "events", []domain.EntityType{domain.EntityProcess, domain.EntityFile}, []string{"self", "tree"}, domain.EventFileCreate, domain.EventFileWrite, domain.EventFileRename, domain.EventFileDelete, domain.EventFileChmod, domain.EventFileChown),
		query("network_connections_query", "查询网络连接", "events", []domain.EntityType{domain.EntityProcess, domain.EntityIP}, []string{"self", "tree"}, domain.EventNetworkConnect, domain.EventNetworkAccept, domain.EventNetworkClose),
		query("dns_events_query", "查询DNS事件", "events", []domain.EntityType{domain.EntityProcess, domain.EntityHost, domain.EntityDomain}, []string{"self", "tree"}, domain.EventDNSQuery, domain.EventDNSResponse),
		query("privilege_events_query", "查询权限变化", "events", []domain.EntityType{domain.EntityProcess, domain.EntityIdentity}, []string{"self", "tree"}, domain.EventSetUID, domain.EventSetGID, domain.EventCapset, domain.EventSudo),
		query("kernel_security_events_query", "查询高价值内核安全事件", "events", []domain.EntityType{domain.EntityProcess}, []string{"self", "tree"}, domain.EventSetNS, domain.EventUnshare, domain.EventMount, domain.EventUmount, domain.EventChroot, domain.EventPivotRoot, domain.EventPtrace, domain.EventBPFLoad, domain.EventModuleLoad),
		query("web_access_events_query", "查询Web入口请求", "web", []domain.EntityType{domain.EntityWorkload, domain.EntityContainer, domain.EntityRequest, domain.EntityIP}, []string{"self", "tree"}, domain.EventHTTPRequest, domain.EventHTTPResponse, domain.EventWAFDecision),
		query("k8s_audit_events_query", "查询Kubernetes审计事件", "kubernetes", []domain.EntityType{domain.EntityWorkload, domain.EntityIdentity, domain.EntityIP}, []string{"self", "tree"}, domain.EventK8sAPIRequest),
		query("cloud_audit_events_query", "查询云控制面事件", "cloud", []domain.EntityType{domain.EntityCloud, domain.EntityIdentity, domain.EntityIP}, []string{"self", "tree"}, domain.EventCloudAPIRequest),
		get("indicator_reputation_lookup", "查询已观察指标信誉", "reputation", "indicator_ref", domain.EntityIP, domain.EntityDomain, domain.EntityFile),
		get("file_metadata_get", "读取文件哈希、签名和包归属", "files", "file_ref", domain.EntityFile),
		get("change_authorization_lookup", "查询变更授权", "changes", "entity_ref", domain.EntityHost, domain.EntityWorkload, domain.EntityIdentity),
		get("entity_baseline_get", "读取实体历史行为基线", "baseline", "entity_ref", domain.EntityIdentity, domain.EntityProcess, domain.EntityWorkload, domain.EntityIP, domain.EntityDomain),
		{Name: "timeline_build", Description: "构建证据时间线", Source: "evidence", Fields: map[string]FieldSpec{"evidence_refs": {Kind: FieldStringArray, Required: true, MaxLength: 500}}},
		{Name: "relationship_validate", Description: "验证实体关系", Source: "evidence", Fields: map[string]FieldSpec{
			"subject_ref": {Kind: FieldString, Required: true, MaxLength: 128}, "predicate": {Kind: FieldString, Required: true, MaxLength: 64},
			"object_ref": {Kind: FieldString, Required: true, MaxLength: 128}, "evidence_refs": {Kind: FieldStringArray, Required: true, MaxLength: 100}}},
		{Name: "coverage_summarize", Description: "汇总工具查询覆盖", Source: "tool_results", Fields: map[string]FieldSpec{"query_refs": {Kind: FieldStringArray, Required: true, MaxLength: 500}}},
	}
}
