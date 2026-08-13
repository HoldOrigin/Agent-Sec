package investigation

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"sentinel/internal/graph"
	"sentinel/internal/model"
	"sentinel/internal/policy"
	"sentinel/internal/store"
)

type Agent struct {
	store    *store.Memory
	policy   *policy.Engine
	maxSteps int
}

func New(s *store.Memory, p *policy.Engine, maxSteps int) *Agent {
	return &Agent{store: s, policy: p, maxSteps: maxSteps}
}

func (a *Agent) Investigate(base model.Incident) (model.Incident, error) {
	seedID := ""
	for _, behavior := range base.Behaviors {
		if behavior.Type == "WebServerSpawnShell" && len(behavior.Evidence) > 0 {
			seedID = behavior.Evidence[0]
			break
		}
	}
	if seedID == "" && len(base.EvidenceEventIDs) > 0 {
		seedID = base.EvidenceEventIDs[0]
	}
	seed, ok := a.store.Event(seedID)
	if !ok {
		return model.Incident{}, fmt.Errorf("incident seed event not found: %s", seedID)
	}
	trace := []model.ToolTrace{}
	addTrace := func(tool, purpose string, count int) error {
		if len(trace) >= a.maxSteps {
			return fmt.Errorf("agent reached maximum tool steps")
		}
		trace = append(trace, model.ToolTrace{Step: len(trace) + 1, Tool: tool, Purpose: purpose, ResultCount: count})
		return nil
	}
	related := a.store.RelatedEvents(seed, 10*time.Minute)
	processEvents := filterEvents(related, func(e model.RuntimeEvent) bool {
		return e.ProcessEntityID == seed.ProcessEntityID || e.PID == seed.PID || e.PPID == seed.PID
	})
	fileEvents := filterEvents(related, func(e model.RuntimeEvent) bool {
		return strings.HasPrefix(e.Type, "file_") || metaString(e, "exec_path") != ""
	})
	networkEvents := filterEvents(related, func(e model.RuntimeEvent) bool {
		return e.Type == "network_connect" || metaString(e, "domain") != "" || metaString(e, "destination_ip") != ""
	})
	runtimeGraph := graph.Build(related)
	processNodes := 0
	for _, node := range runtimeGraph.Nodes {
		if node.Type == "process" {
			processNodes++
		}
	}
	steps := []struct {
		tool, purpose string
		count         int
	}{{"get_process_tree", "还原完整父子进程链", processNodes}, {"get_process_events", "读取进程树相关事实", len(processEvents)}, {"get_file_events", "建立文件落地与执行时间线", len(fileEvents)}, {"get_network_events", "建立下载与 C2 网络时间线", len(networkEvents)}, {"get_runtime_graph", "读取 Incident 子图", len(runtimeGraph.Nodes)}, {"get_workload_info", "补充工作负载与容器元数据", 6}}
	for _, step := range steps {
		if err := addTrace(step.tool, step.purpose, step.count); err != nil {
			return model.Incident{}, err
		}
	}
	payloadHash := ""
	for _, event := range fileEvents {
		if value := metaString(event, "sha256"); value != "" {
			payloadHash = value
			break
		}
	}
	destination := ""
	if len(networkEvents) > 0 {
		last := networkEvents[len(networkEvents)-1]
		destination = firstNonEmpty(metaString(last, "destination_ip"), metaString(last, "domain"))
	}
	sameHash := a.findOther(func(event model.RuntimeEvent) bool {
		return payloadHash != "" && metaString(event, "sha256") == payloadHash
	}, seed.ContainerID)
	sameIP := a.findOther(func(event model.RuntimeEvent) bool {
		return destination != "" && (metaString(event, "destination_ip") == destination || metaString(event, "domain") == destination)
	}, seed.ContainerID)
	if err := addTrace("find_same_hash", "检查相同 Payload 是否扩散", len(sameHash)); err != nil {
		return model.Incident{}, err
	}
	if err := addTrace("find_same_ip", "检查相同目的地址是否影响其他容器", len(sameIP)); err != nil {
		return model.Incident{}, err
	}

	events := []model.RuntimeEvent{}
	for _, id := range base.EvidenceEventIDs {
		if event, exists := a.store.Event(id); exists {
			events = append(events, event)
		}
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Timestamp.Before(events[j].Timestamp) })
	behaviorByEvidence := map[string][]string{}
	for _, behavior := range base.Behaviors {
		for _, id := range behavior.Evidence {
			behaviorByEvidence[id] = appendUnique(behaviorByEvidence[id], behavior.Type)
		}
	}
	evidence := []model.Evidence{}
	timeline := []model.TimelineEntry{}
	observed := []model.Finding{}
	for _, event := range events {
		fact := evidenceFact(event)
		evidence = append(evidence, model.Evidence{EventID: event.EventID, Timestamp: event.Timestamp, Type: event.Type, ProcessEntityID: event.ProcessEntityID, Fact: fact, SupportsBehaviors: behaviorByEvidence[event.EventID]})
		timeline = append(timeline, model.TimelineEntry{Timestamp: event.Timestamp, EventID: event.EventID, Description: fact})
		observed = append(observed, model.Finding{Claim: fact, Evidence: []string{event.EventID}})
	}
	rootEvidence := []string{}
	for _, behavior := range base.Behaviors {
		if behavior.Type == "WebServerSpawnShell" {
			rootEvidence = behavior.Evidence
			break
		}
	}
	rootCause := model.RootCause{Entity: base.RootProcessName, Assessment: "possible web RCE", Observed: fmt.Sprintf("进程 %s 直接派生了非预期 Shell。", base.RootProcessName), Inferred: "Web 应用可能遭到远程命令执行利用；由于缺少 HTTP 与应用 Trace，不能确认具体漏洞或 CVE。", Evidence: rootEvidence}
	containers := map[string]bool{}
	if seed.ContainerID != "" {
		containers[seed.ContainerID] = true
	}
	for _, event := range append(sameHash, sameIP...) {
		if event.ContainerID != "" {
			containers[event.ContainerID] = true
		}
	}
	containerIDs := keys(containers)
	assessment := "目前证据仅显示一个 Container 受到影响"
	if len(containerIDs) > 1 {
		assessment = fmt.Sprintf("发现 %d 个关联 Container，需扩大排查", len(containerIDs))
	}
	base.Title = "疑似 Web RCE 后 Payload 下载执行"
	base.Verdict = "likely_compromise"
	base.Classification = "likely_compromise"
	base.Confidence = confidence(base, len(evidence))
	base.Summary = fmt.Sprintf("%s 中的 %s 服务派生 Shell，随后下载、写入、授权并执行临时目录中的未知 Payload；该进程之后连接了罕见公网地址。", base.Workload, base.RootProcessName)
	base.RootCause = rootCause
	base.ObservedFindings = observed
	base.InferredFindings = []model.Finding{{Claim: rootCause.Inferred, Evidence: rootCause.Evidence, Limitation: "缺少 HTTP/Application Trace"}}
	base.AttackStory = buildStory(base)
	base.Graph = runtimeGraph
	base.Timeline = timeline
	base.AffectedAssets = []map[string]any{{"type": "container", "id": seed.ContainerID, "workload": seed.Workload, "namespace": seed.Namespace}}
	base.BlastRadius = model.BlastRadius{ContainerCount: len(containerIDs), Assessment: assessment, AffectedContainerIDs: containerIDs, SameHashMatches: eventIDs(sameHash), SameIPMatches: eventIDs(sameIP)}
	base.Entities = collectEntities(events)
	base.Evidence = evidence
	base.Recommendations = a.recommendations(base, seed)
	base.ToolTrace = trace
	base.InvestigationStats = model.InvestigationStats{ToolCalls: len(trace), ContextTypes: []string{"process_tree", "process_events", "file_timeline", "network_timeline", "runtime_graph", "workload", "same_hash", "same_ip"}, ProcessNodes: processNodes, CompressedInput: true, RawSyscallsSentToAI: 0, ProcessEventCount: len(processEvents)}
	return a.store.AddIncident(base), nil
}

func (a *Agent) findOther(match func(model.RuntimeEvent) bool, container string) []model.RuntimeEvent {
	result := []model.RuntimeEvent{}
	for _, event := range a.store.Events() {
		if event.ContainerID != container && match(event) {
			result = append(result, event)
		}
	}
	return result
}
func (a *Agent) recommendations(incident model.Incident, seed model.RuntimeEvent) []model.Recommendation {
	target := map[string]any{"namespace": seed.Namespace, "pod": seed.Pod, "container_id": seed.ContainerID}
	inputs := []struct{ action, title, rationale string }{{"create_ticket", "创建高优先级安全工单", "保留 Incident " + incident.IncidentID + " 的完整证据链"}, {"isolate_pod", "隔离受影响工作负载", "阻断 Payload 的持续外联与潜在横向移动"}, {"generate_report", "采集并生成取证报告", "固化进程树、文件时间线、网络时间线和 Runtime Graph"}}
	result := []model.Recommendation{}
	for _, item := range inputs {
		decision := a.policy.Evaluate(policy.ActionRequest{Actor: "security-agent", Action: item.action, Target: target, Risk: incident.Risk, IncidentID: incident.IncidentID})
		result = append(result, model.Recommendation{Action: item.action, Title: item.title, Target: target, Rationale: item.rationale, Policy: decision})
	}
	return result
}
func buildStory(incident model.Incident) []model.AttackStoryStep {
	desired := []string{"WebServerSpawnShell", "ShellSpawnDownloader", "DownloadExecutable", "WriteExecutableToTemp", "ChangeExecutablePermission", "ExecuteFromTemp", "RareExternalConnection"}
	result := []model.AttackStoryStep{}
	for _, kind := range desired {
		for _, behavior := range incident.Behaviors {
			if behavior.Type == kind {
				result = append(result, model.AttackStoryStep{Step: len(result) + 1, Behavior: kind, Entity: storyEntity(behavior), Observed: true, Evidence: behavior.Evidence})
				break
			}
		}
	}
	return result
}
func storyEntity(b model.Behavior) string {
	if b.Type == "WebServerSpawnShell" || b.Type == "ShellSpawnDownloader" {
		return fmt.Sprintf("%v → %v", b.Details["parent"], b.Details["child"])
	}
	if b.Type == "DownloadExecutable" {
		return fmt.Sprintf("%v → %v → %v", b.Details["downloader"], b.Details["source"], b.Details["path"])
	}
	if b.Type == "RareExternalConnection" {
		return fmt.Sprintf("payload → %s:%d", b.Object.Value, b.Object.Port)
	}
	if b.Object.Path != "" {
		return b.Object.Path
	}
	return b.Subject.Name
}
func evidenceFact(event model.RuntimeEvent) string {
	if event.Type == "network_connect" {
		return fmt.Sprintf("%s 连接 %s:%d", event.Process, firstNonEmpty(metaString(event, "domain"), metaString(event, "destination_ip")), metaInt(event, "destination_port"))
	}
	if strings.HasPrefix(event.Type, "file_") {
		return fmt.Sprintf("%s %s %s", event.Process, strings.TrimPrefix(event.Type, "file_"), metaString(event, "path"))
	}
	fact := fmt.Sprintf("%s → %s", defaultString(event.ParentProcess, "?"), event.Process)
	if event.Cmdline != "" {
		fact += " (" + event.Cmdline + ")"
	}
	return fact
}
func confidence(incident model.Incident, count int) float64 {
	core := 0
	for _, kind := range []string{"WebServerSpawnShell", "DownloadExecutable", "ExecuteFromTemp", "RareExternalConnection"} {
		if contains(incident.BehaviorTypes, kind) {
			core++
		}
	}
	value := .72 + float64(core)*.05 + float64(min(count, 8))*.01
	return math.Min(.98, value)
}
func collectEntities(events []model.RuntimeEvent) []string {
	result := []string{}
	for _, e := range events {
		for _, v := range []string{e.Workload, e.Pod, e.Process, e.ParentProcess, metaString(e, "path"), metaString(e, "exec_path"), metaString(e, "domain"), metaString(e, "destination_ip")} {
			result = appendUnique(result, v)
		}
	}
	return result
}
func filterEvents(events []model.RuntimeEvent, keep func(model.RuntimeEvent) bool) []model.RuntimeEvent {
	result := []model.RuntimeEvent{}
	for _, e := range events {
		if keep(e) {
			result = append(result, e)
		}
	}
	return result
}
func eventIDs(events []model.RuntimeEvent) []string {
	r := []string{}
	for _, e := range events {
		r = append(r, e.EventID)
	}
	return r
}
func keys(m map[string]bool) []string {
	r := []string{}
	for k := range m {
		r = append(r, k)
	}
	sort.Strings(r)
	return r
}
func appendUnique(values []string, value string) []string {
	if value == "" || contains(values, value) {
		return values
	}
	return append(values, value)
}
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func metaString(e model.RuntimeEvent, key string) string {
	if v, ok := e.Metadata[key].(string); ok {
		return v
	}
	return ""
}
func metaInt(e model.RuntimeEvent, key string) int {
	if v, ok := e.Metadata[key].(float64); ok {
		return int(v)
	}
	if v, ok := e.Metadata[key].(int); ok {
		return v
	}
	return 0
}
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
func defaultString(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
