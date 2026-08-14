package collector

import (
	"net"
	"path/filepath"
	"strconv"
	"strings"
)

type UploadMode string

const (
	UploadAlways    UploadMode = "ALWAYS"
	UploadOnAlert   UploadMode = "ON_ALERT"
	UploadAggregate UploadMode = "AGGREGATE"
	UploadLocalOnly UploadMode = "LOCAL_ONLY"
)

type UploadPriority string

const (
	PriorityHigh   UploadPriority = "high"
	PriorityNormal UploadPriority = "normal"
)

type UploadDecision struct {
	Mode           UploadMode
	Priority       UploadPriority
	Reason         string
	PromoteContext bool
}

type UploadPolicy interface {
	Decide(event map[string]any) UploadDecision
}

// DefaultUploadPolicy deliberately contains only inexpensive, deterministic
// predicates. A later DetectionPolicy (for example CEL) can mark an event with
// metadata.security_alert or metadata.blacklist_hit before this policy runs.
type DefaultUploadPolicy struct{}

func NewDefaultUploadPolicy() *DefaultUploadPolicy { return &DefaultUploadPolicy{} }

func (*DefaultUploadPolicy) Decide(event map[string]any) UploadDecision {
	eventType := eventString(event, "event_type")
	metadata := eventMap(event, "metadata")
	if valueBool(metadata["blacklist_hit"]) || valueBool(metadata["security_alert"]) {
		return UploadDecision{Mode: UploadAlways, Priority: PriorityHigh, Reason: firstString(valueString(metadata["detection_reason"]), "local_security_rule"), PromoteContext: true}
	}
	if valueString(metadata["collection_level"]) == "INVESTIGATION" {
		return UploadDecision{Mode: UploadAlways, Priority: PriorityHigh, Reason: "investigation_collection"}
	}

	switch eventType {
	case "process_exec", "file_create", "file_write", "file_chmod", "file_unlink":
		return UploadDecision{Mode: UploadOnAlert, Priority: PriorityHigh, Reason: "retain_for_alert_context"}
	case "network_connect":
		if isPublicDestination(valueString(metadata["destination_ip"])) {
			return UploadDecision{Mode: UploadOnAlert, Priority: PriorityHigh, Reason: "external_connection_context"}
		}
		return UploadDecision{Mode: UploadAggregate, Priority: PriorityNormal, Reason: "stable_network_baseline"}
	case "network_accept", "dns_query", "process_fork", "process_exit":
		return UploadDecision{Mode: UploadAggregate, Priority: PriorityNormal, Reason: "high_frequency_baseline"}
	case "file_open", "file_read":
		return UploadDecision{Mode: UploadLocalOnly, Priority: PriorityNormal, Reason: "low_value_read_activity"}
	default:
		return UploadDecision{Mode: UploadOnAlert, Priority: PriorityNormal, Reason: "unknown_event_retained_locally"}
	}
}

func alwaysEventType(eventType string) bool {
	switch eventType {
	case "namespace_change", "mount", "umount", "root_change", "privilege_change", "ptrace", "security_alert":
		return true
	default:
		return false
	}
}

func isFileMutation(eventType string) bool {
	switch eventType {
	case "file_create", "file_write", "file_chmod", "file_unlink", "file_rename":
		return true
	default:
		return false
	}
}

func isTempRuntimePath(path string) bool {
	cleaned := filepath.ToSlash(filepath.Clean(path))
	return strings.HasPrefix(cleaned, "/tmp/") || strings.HasPrefix(cleaned, "/var/tmp/") || strings.HasPrefix(cleaned, "/dev/shm/")
}

func isSensitiveRuntimePath(path string) bool {
	cleaned := filepath.ToSlash(filepath.Clean(path))
	for _, prefix := range []string{"/etc/", "/root/", "/boot/", "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/"} {
		if strings.HasPrefix(cleaned, prefix) {
			return true
		}
	}
	return false
}

func isPublicDestination(value string) bool {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return value != ""
	}
	return !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified()
}

func isWebProcess(value string) bool {
	switch value {
	case "java", "nginx", "php-fpm", "node", "python", "gunicorn", "uwsgi":
		return true
	default:
		return false
	}
}

func isShell(value string) bool {
	switch value {
	case "sh", "bash", "dash", "zsh":
		return true
	default:
		return false
	}
}

func eventScopeKey(event map[string]any) string {
	container := eventMap(event, "container")
	if cgroup := valueString(container["cgroup_id"]); cgroup != "" && cgroup != "0" {
		return "cgroup:" + cgroup
	}
	if containerID := valueString(container["container_id"]); containerID != "" {
		return "container:" + containerID
	}
	host := eventMap(event, "host")
	process := eventMap(event, "process")
	return "process:" + valueString(host["host_id"]) + ":" + valueString(process["pid"])
}

func eventAggregationKey(event map[string]any) string {
	eventType := eventString(event, "event_type")
	metadata := eventMap(event, "metadata")
	process := eventMap(event, "process")
	parts := []string{eventScopeKey(event), eventType, valueString(process["exe"])}
	switch eventType {
	case "network_connect", "network_accept":
		parts = append(parts, valueString(metadata["destination_ip"]), valueString(metadata["destination_port"]), valueString(metadata["protocol"]))
	case "dns_query":
		parts = append(parts, valueString(metadata["query"]), valueString(metadata["query_type"]))
	default:
		parts = append(parts, valueString(metadata["path"]))
	}
	return strings.Join(parts, "|")
}

func eventMap(value map[string]any, key string) map[string]any {
	if mapped, ok := value[key].(map[string]any); ok {
		return mapped
	}
	return map[string]any{}
}

func eventString(value map[string]any, key string) string { return valueString(value[key]) }

func valueString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case int:
		return strconv.Itoa(typed)
	case int32:
		return strconv.FormatInt(int64(typed), 10)
	case uint32:
		return strconv.FormatUint(uint64(typed), 10)
	case int64:
		return strconv.FormatInt(typed, 10)
	case uint64:
		return strconv.FormatUint(typed, 10)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return ""
	}
}

func valueBool(value any) bool { result, _ := value.(bool); return result }

func firstString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
