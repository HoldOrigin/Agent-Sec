package processor

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"sentinel/internal/model"
)

var supported = map[string]bool{
	"process_fork": true, "process_exec": true, "process_exit": true,
	"file_open": true, "file_create": true, "file_write": true, "file_rename": true, "file_unlink": true, "file_chmod": true,
	"network_connect": true, "network_accept": true,
}

type cachedFile struct {
	EventID   string
	Timestamp time.Time
}

type Processor struct {
	mu            sync.Mutex
	cacheTTL      time.Duration
	fingerprints  map[string]time.Time
	fileCache     map[string][]cachedFile
	processStarts map[string]string
	stats         model.ProcessorStats
}

func New(cacheTTL time.Duration) *Processor {
	p := &Processor{cacheTTL: cacheTTL}
	p.Reset()
	return p
}

func (p *Processor) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.fingerprints = map[string]time.Time{}
	p.fileCache = map[string][]cachedFile{}
	p.processStarts = map[string]string{}
	p.stats = model.ProcessorStats{}
}

func (p *Processor) Stats() model.ProcessorStats { p.mu.Lock(); defer p.mu.Unlock(); return p.stats }

func (p *Processor) Process(input map[string]any) (model.ProcessResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stats.Received++
	event, inferred, err := normalize(input)
	if err != nil {
		return model.ProcessResult{}, err
	}
	p.stabilize(&event, inferred)
	fingerprint := event.EventID
	if fingerprint == "" {
		fingerprint = fingerprintFor(event)
	}
	if _, exists := p.fingerprints[fingerprint]; exists {
		p.stats.Deduplicated++
		return model.ProcessResult{Dropped: "duplicate", PromotedEventIDs: []string{}}, nil
	}
	p.fingerprints[fingerprint] = event.Timestamp
	p.expire(event.Timestamp)
	if !supported[event.Type] {
		p.stats.Filtered++
		return model.ProcessResult{Dropped: "unsupported_event_type", PromotedEventIDs: []string{}}, nil
	}
	if shouldFilter(event) {
		p.stats.Filtered++
		return model.ProcessResult{Dropped: "agent_filter", PromotedEventIDs: []string{}}, nil
	}
	path := metaString(event.Metadata, "path")
	if path == "" {
		path = metaString(event.Metadata, "exec_path")
	}
	promoted := []string{}
	if IsTempPath(path) {
		cached := p.fileCache[path]
		if event.Type == "file_write" || event.Type == "file_create" {
			cached = append(cached, cachedFile{event.EventID, event.Timestamp})
			p.fileCache[path] = cached
		}
		if event.Type == "file_chmod" || (event.Type == "process_exec" && metaString(event.Metadata, "exec_path") == path) {
			for _, item := range cached {
				promoted = append(promoted, item.EventID)
			}
			if len(promoted) > 0 {
				event.Metadata["promoted_related_event_ids"] = promoted
				event.Metadata["security_relevant"] = true
				p.stats.Promoted += len(promoted)
			}
		}
	}
	p.stats.Accepted++
	return model.ProcessResult{Accepted: []model.RuntimeEvent{event}, PromotedEventIDs: promoted}, nil
}

func (p *Processor) stabilize(event *model.RuntimeEvent, inferred bool) {
	key := fmt.Sprintf("%s:%s:%d", event.Host, event.BootID, event.PID)
	if !inferred || p.processStarts[key] == "" {
		p.processStarts[key] = event.ProcessStartTime
	} else {
		event.ProcessStartTime = p.processStarts[key]
		event.ProcessEntityID = ProcessEntityID(event.Host, event.BootID, event.PID, event.ProcessStartTime)
	}
	parentKey := fmt.Sprintf("%s:%s:%d", event.Host, event.BootID, event.PPID)
	if parentStart := p.processStarts[parentKey]; parentStart != "" {
		event.ParentProcessEntityID = ProcessEntityID(event.Host, event.BootID, event.PPID, parentStart)
	}
}

func (p *Processor) expire(now time.Time) {
	for path, items := range p.fileCache {
		live := items[:0]
		for _, item := range items {
			if now.Sub(item.Timestamp) <= p.cacheTTL {
				live = append(live, item)
			}
		}
		if len(live) == 0 {
			delete(p.fileCache, path)
		} else {
			p.fileCache[path] = live
		}
	}
	for key, timestamp := range p.fingerprints {
		if now.Sub(timestamp) > p.cacheTTL*5 {
			delete(p.fingerprints, key)
		}
	}
}

func normalize(input map[string]any) (model.RuntimeEvent, bool, error) {
	metadata := mapValue(input["metadata"])
	timestamp, err := parseTime(input["timestamp"])
	if err != nil {
		return model.RuntimeEvent{}, false, fmt.Errorf("invalid timestamp: %w", err)
	}
	hostObj := mapValue(input["host"])
	processObj := mapValue(input["process"])
	containerObj := mapValue(input["container"])
	nested := len(hostObj) > 0 || len(processObj) > 0 || stringValue(input["event_type"]) != ""
	host := stringValue(input["host"])
	if nested {
		host = stringValue(hostObj["host_id"])
	}
	typeName := stringValue(input["event_type"])
	if typeName == "" {
		typeName = stringValue(input["type"])
	}
	pid := intValue(input["pid"])
	ppid := intValue(input["ppid"])
	exe := stringValue(input["process"])
	argv := stringSlice(input["argv"])
	uid := input["user"]
	if nested {
		pid = intValue(processObj["pid"])
		ppid = intValue(processObj["ppid"])
		exe = stringValue(processObj["exe"])
		argv = stringSlice(processObj["argv"])
		uid = processObj["uid"]
	}
	cmdline := stringValue(input["cmdline"])
	if cmdline == "" {
		cmdline = strings.Join(argv, " ")
	}
	if len(argv) == 0 && cmdline != "" {
		argv = strings.Fields(cmdline)
	}
	start := stringValue(processObj["start_time"])
	if start == "" {
		start = stringValue(input["process_start_time"])
	}
	inferred := start == ""
	if inferred {
		start = timestamp.Format(time.RFC3339Nano)
		metadata["process_start_time_inferred"] = true
	}
	boot := stringValue(hostObj["boot_id"])
	if boot == "" {
		boot = stringValue(input["boot_id"])
	}
	if boot == "" {
		boot = metaString(metadata, "boot_id")
	}
	if boot == "" {
		boot = "boot-unknown"
	}
	containerID := stringValue(input["container_id"])
	if nested {
		containerID = stringValue(containerObj["container_id"])
	}
	pod := firstNonEmpty(stringValue(containerObj["pod"]), stringValue(input["pod"]))
	workload := firstNonEmpty(stringValue(containerObj["workload"]), stringValue(input["workload"]), pod)
	parentStart := metaString(metadata, "parent_start_time")
	if parentStart == "" {
		parentStart = "unknown"
	}
	return model.RuntimeEvent{
		EventID: stringValue(input["event_id"]), Timestamp: timestamp, Type: typeName, EventType: typeName, Host: host, HostID: host, BootID: boot,
		PID: pid, PPID: ppid, Process: filepath.Base(exe), Exe: exe, Argv: argv, Cmdline: cmdline,
		ParentProcess: firstNonEmpty(stringValue(input["parent_process"]), metaString(metadata, "parent_process")), ProcessStartTime: start,
		ProcessEntityID: ProcessEntityID(host, boot, pid, start), ParentProcessEntityID: ProcessEntityID(host, boot, ppid, parentStart), UID: uid,
		ContainerID: containerID, PodUID: firstNonEmpty(stringValue(containerObj["pod_uid"]), stringValue(input["pod_uid"])), Pod: pod, Workload: workload,
		Namespace: firstNonEmpty(stringValue(containerObj["namespace"]), stringValue(input["namespace"])), CgroupID: firstNonEmpty(stringValue(containerObj["cgroup_id"]), stringValue(input["cgroup_id"])), Metadata: metadata,
	}, inferred, nil
}

func ProcessEntityID(host, boot string, pid int, start string) string {
	return fmt.Sprintf("proc://%s/%s/%d/%s", url.PathEscape(defaultString(host, "unknown")), url.PathEscape(defaultString(boot, "unknown")), pid, url.PathEscape(defaultString(start, "unknown")))
}

func IsTempPath(path string) bool {
	return strings.HasPrefix(path, "/tmp/") || strings.HasPrefix(path, "/var/tmp/") || strings.HasPrefix(path, "/dev/shm/")
}

func IsPublicAddress(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	if parsed, err := url.Parse(value); err == nil && parsed.Hostname() != "" {
		value = parsed.Hostname()
	}
	value = strings.Split(strings.Split(value, "/")[0], ":")[0]
	if strings.EqualFold(value, "localhost") {
		return false
	}
	if ip := net.ParseIP(value); ip != nil {
		return !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified()
	}
	return true
}

func shouldFilter(event model.RuntimeEvent) bool {
	if metaBool(event.Metadata, "agent_process") || metaBool(event.Metadata, "kernel_thread") || metaBool(event.Metadata, "excluded_pid") || metaBool(event.Metadata, "excluded_uid") || metaBool(event.Metadata, "excluded_cgroup") {
		return true
	}
	if event.Type == "file_open" {
		path := metaString(event.Metadata, "path")
		return !IsTempPath(path) && !metaBool(event.Metadata, "sensitive") && !metaBool(event.Metadata, "executable") && !metaBool(event.Metadata, "new_file")
	}
	return false
}

func fingerprintFor(event model.RuntimeEvent) string {
	data, _ := json.Marshal([]any{event.Timestamp, event.Type, event.Host, event.ProcessEntityID, event.Metadata["path"], event.Metadata["destination_ip"], event.Cmdline})
	sum := sha1.Sum(data)
	return hex.EncodeToString(sum[:])
}

func parseTime(value any) (time.Time, error) {
	switch v := value.(type) {
	case float64:
		if v < 1e10 {
			v *= 1000
		}
		return time.UnixMilli(int64(v)).UTC(), nil
	case int64:
		if v < 1e10 {
			return time.Unix(v, 0).UTC(), nil
		}
		return time.UnixMilli(v).UTC(), nil
	case json.Number:
		f, e := strconv.ParseFloat(string(v), 64)
		if e != nil {
			return time.Time{}, e
		}
		return parseTime(f)
	case string:
		if v == "" {
			return time.Now().UTC(), nil
		}
		return time.Parse(time.RFC3339Nano, v)
	case nil:
		return time.Now().UTC(), nil
	default:
		return time.Time{}, fmt.Errorf("unsupported timestamp %T", value)
	}
}

func mapValue(value any) map[string]any {
	if v, ok := value.(map[string]any); ok {
		return cloneMap(v)
	}
	return map[string]any{}
}
func cloneMap(value map[string]any) map[string]any {
	r := make(map[string]any, len(value))
	for k, v := range value {
		r[k] = v
	}
	return r
}
func stringValue(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case json.Number:
		return string(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case int:
		return strconv.Itoa(v)
	case nil:
		return ""
	default:
		return ""
	}
}
func intValue(value any) int {
	switch v := value.(type) {
	case int:
		return v
	case float64:
		return int(v)
	case json.Number:
		i, _ := strconv.Atoi(string(v))
		return i
	case string:
		i, _ := strconv.Atoi(v)
		return i
	default:
		return 0
	}
}
func stringSlice(value any) []string {
	values, ok := value.([]any)
	if ok {
		r := make([]string, 0, len(values))
		for _, v := range values {
			r = append(r, stringValue(v))
		}
		return r
	}
	if v, ok := value.([]string); ok {
		return append([]string{}, v...)
	}
	return []string{}
}
func metaString(m map[string]any, key string) string { return stringValue(m[key]) }
func metaBool(m map[string]any, key string) bool     { v, ok := m[key].(bool); return ok && v }
func defaultString(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
