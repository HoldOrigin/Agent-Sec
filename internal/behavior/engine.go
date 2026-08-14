package behavior

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"sentinel/internal/model"
	"sentinel/internal/processor"
)

var Definitions = map[string]model.BehaviorDefinition{
	"B001": {Type: "WebServerSpawnShell", RiskScore: 30}, "B002": {Type: "ShellSpawnDownloader", RiskScore: 10},
	"B003": {Type: "DownloadExecutable", RiskScore: 15}, "B004": {Type: "WriteExecutableToTemp", RiskScore: 10},
	"B005": {Type: "ChangeExecutablePermission", RiskScore: 10}, "B006": {Type: "ExecuteFromTemp", RiskScore: 25},
	"B007": {Type: "UnknownBinaryExecution", RiskScore: 10}, "B008": {Type: "RareExternalConnection", RiskScore: 20},
	"B900": {Type: "LocalSecurityPolicyMatch", RiskScore: 90},
}
var webProcesses = stringSet("java", "nginx", "php-fpm", "node", "python", "gunicorn", "uwsgi")
var shells = stringSet("sh", "bash", "dash", "zsh")
var downloaders = stringSet("curl", "wget")

type Engine struct{}

func New() *Engine { return &Engine{} }

func (e *Engine) Derive(events []model.RuntimeEvent) []model.Behavior {
	ordered := append([]model.RuntimeEvent{}, events...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Timestamp.Before(ordered[j].Timestamp) })
	result := []model.Behavior{}
	seen := map[string]bool{}
	add := func(code string, event model.RuntimeEvent, object model.EntityRef, evidence []model.RuntimeEvent, details map[string]any) {
		ids := []string{}
		idSeen := map[string]bool{}
		for _, item := range evidence {
			if item.EventID != "" && !idSeen[item.EventID] {
				idSeen[item.EventID] = true
				ids = append(ids, item.EventID)
			}
		}
		key := code + ":" + strings.Join(ids, ":")
		if seen[key] {
			return
		}
		seen[key] = true
		def := Definitions[code]
		result = append(result, model.Behavior{BehaviorID: "beh-" + strings.ToLower(code) + "-" + shortHash(key), Code: code, Type: def.Type, Timestamp: event.Timestamp, Subject: model.EntityRef{Type: "process", ID: event.ProcessEntityID, Name: event.Process}, Object: object, RiskScore: def.RiskScore, Evidence: ids, Scope: model.Scope{HostID: event.Host, ContainerID: event.ContainerID, Workload: event.Workload, Namespace: event.Namespace}, ProcessTreeID: fmt.Sprintf("%s:%s:%d:%d", event.Host, event.ContainerID, event.PID, event.PPID), CorrelationKey: key, Details: details})
	}
	for _, event := range ordered {
		if metaBool(event, "security_alert") {
			add("B900", event, model.EntityRef{Type: "process", ID: event.ProcessEntityID, Name: event.Process}, []model.RuntimeEvent{event}, map[string]any{
				"rule_id":   firstNonEmpty(metaString(event, "detection_rule_id"), "LOCAL-DETECTION"),
				"severity":  firstNonEmpty(metaString(event, "detection_severity"), "high"),
				"reason":    firstNonEmpty(metaString(event, "detection_reason"), "local runtime security policy matched"),
				"blacklist": metaBool(event, "blacklist_hit"),
			})
		}
		if event.Type == "process_exec" && webProcesses[event.ParentProcess] && shells[event.Process] {
			add("B001", event, model.EntityRef{Type: "process", ID: event.ProcessEntityID, Name: event.Process}, []model.RuntimeEvent{event}, map[string]any{"parent": event.ParentProcess, "child": event.Process})
		}
		if event.Type == "process_exec" && shells[event.ParentProcess] && downloaders[event.Process] {
			add("B002", event, model.EntityRef{Type: "process", ID: event.ProcessEntityID, Name: event.Process}, []model.RuntimeEvent{event}, map[string]any{"parent": event.ParentProcess, "child": event.Process})
		}
		path := metaString(event, "path")
		if path == "" {
			path = metaString(event, "exec_path")
		}
		if (event.Type == "file_write" || event.Type == "file_create") && processor.IsTempPath(path) {
			later := []model.RuntimeEvent{}
			for _, candidate := range ordered {
				if sameScope(event, candidate) && !candidate.Timestamp.Before(event.Timestamp) && candidate.Timestamp.Sub(event.Timestamp) <= time.Minute && ((candidate.Type == "file_chmod" && metaString(candidate, "path") == path) || (candidate.Type == "process_exec" && metaString(candidate, "exec_path") == path)) {
					later = append(later, candidate)
				}
			}
			if metaBool(event, "executable") || metaBool(event, "elf") || len(later) > 0 {
				evidence := append([]model.RuntimeEvent{event}, later...)
				format := "inferred_executable"
				if metaBool(event, "elf") {
					format = "ELF"
				}
				add("B004", event, model.EntityRef{Type: "file", Path: path}, evidence, map[string]any{"executable": true, "format": format})
			}
		}
		if event.Type == "file_chmod" && processor.IsTempPath(path) && executableMode(metaString(event, "mode")) {
			add("B005", event, model.EntityRef{Type: "file", Path: path}, []model.RuntimeEvent{event}, map[string]any{"mode": metaString(event, "mode")})
		}
		if event.Type == "process_exec" && processor.IsTempPath(firstNonEmpty(metaString(event, "exec_path"), event.Exe)) {
			execPath := firstNonEmpty(metaString(event, "exec_path"), event.Exe)
			add("B006", event, model.EntityRef{Type: "file", Path: execPath}, []model.RuntimeEvent{event}, map[string]any{"path": execPath})
			firstSeen, hasFirst := event.Metadata["first_seen"].(bool)
			if metaFalse(event, "package_source") || metaFalse(event, "image_present") || !hasFirst || firstSeen {
				add("B007", event, model.EntityRef{Type: "file", Path: execPath, Hash: metaString(event, "sha256")}, []model.RuntimeEvent{event}, map[string]any{"first_seen": !hasFirst || firstSeen, "package_source": event.Metadata["package_source"]})
			}
		}
		if event.Type == "network_connect" {
			dest := firstNonEmpty(metaString(event, "domain"), metaString(event, "destination_ip"))
			fromTemp := processor.IsTempPath(event.Exe) || processor.IsTempPath(metaString(event, "process_exe"))
			if !fromTemp {
				for _, candidate := range ordered {
					if candidate.PID == event.PID && candidate.Type == "process_exec" && processor.IsTempPath(firstNonEmpty(metaString(candidate, "exec_path"), candidate.Exe)) {
						fromTemp = true
						break
					}
				}
			}
			occurrence := metaInt(event, "baseline_occurrence_30d")
			if fromTemp && occurrence <= 1 && processor.IsPublicAddress(dest) {
				kind := "ip"
				if metaString(event, "domain") != "" {
					kind = "domain"
				}
				add("B008", event, model.EntityRef{Type: kind, Value: dest, Port: metaInt(event, "destination_port")}, []model.RuntimeEvent{event}, map[string]any{"occurrence_30d": occurrence})
			}
		}
	}
	for _, downloader := range ordered {
		if downloader.Type != "process_exec" || !downloaders[downloader.Process] || findURL(downloader) == "" {
			continue
		}
		for _, file := range ordered {
			if sameScope(downloader, file) && file.PID == downloader.PID && (file.Type == "file_create" || file.Type == "file_write") && processor.IsTempPath(metaString(file, "path")) && !file.Timestamp.Before(downloader.Timestamp) && file.Timestamp.Sub(downloader.Timestamp) <= time.Minute && processor.IsPublicAddress(findURL(downloader)) {
				add("B003", file, model.EntityRef{Type: "file", Path: metaString(file, "path"), Source: findURL(downloader)}, []model.RuntimeEvent{downloader, file}, map[string]any{"downloader": downloader.Process, "source": findURL(downloader), "path": metaString(file, "path")})
				break
			}
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Timestamp.Before(result[j].Timestamp) })
	return result
}

func findURL(event model.RuntimeEvent) string {
	if v := firstNonEmpty(metaString(event, "domain"), metaString(event, "source_url")); v != "" {
		return v
	}
	for _, arg := range event.Argv {
		if strings.HasPrefix(arg, "http://") || strings.HasPrefix(arg, "https://") {
			return arg
		}
	}
	for _, part := range strings.Fields(event.Cmdline) {
		if strings.HasPrefix(part, "http://") || strings.HasPrefix(part, "https://") {
			return part
		}
	}
	return ""
}
func executableMode(value string) bool {
	if strings.Contains(value, "x") {
		return true
	}
	n, err := strconv.ParseInt(value, 8, 64)
	return err == nil && n&0111 != 0
}
func sameScope(a, b model.RuntimeEvent) bool {
	return a.Host == b.Host && (a.ContainerID == "" || a.ContainerID == b.ContainerID)
}
func metaString(e model.RuntimeEvent, key string) string {
	if v, ok := e.Metadata[key].(string); ok {
		return v
	}
	return ""
}
func metaBool(e model.RuntimeEvent, key string) bool { v, ok := e.Metadata[key].(bool); return ok && v }
func metaFalse(e model.RuntimeEvent, key string) bool {
	v, ok := e.Metadata[key].(bool)
	return ok && !v
}
func metaInt(e model.RuntimeEvent, key string) int {
	switch v := e.Metadata[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		i, _ := strconv.Atoi(v)
		return i
	}
	return 0
}
func stringSet(values ...string) map[string]bool {
	r := map[string]bool{}
	for _, v := range values {
		r[v] = true
	}
	return r
}
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
func shortHash(v string) string { sum := sha1.Sum([]byte(v)); return hex.EncodeToString(sum[:])[:10] }
