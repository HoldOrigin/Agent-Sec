package incident

import (
	"crypto/sha1"
	"encoding/hex"
	"sort"
	"time"

	"sentinel/internal/model"
)

type Engine struct{ window time.Duration }

func New(window time.Duration) *Engine { return &Engine{window: window} }

func (e *Engine) Correlate(behaviors []model.Behavior, events []model.RuntimeEvent) []model.Incident {
	groups := map[string][]model.Behavior{}
	for _, item := range behaviors {
		key := item.Scope.HostID + ":" + defaultString(item.Scope.ContainerID, "host")
		groups[key] = append(groups[key], item)
	}
	result := []model.Incident{}
	for key, items := range groups {
		sort.Slice(items, func(i, j int) bool { return items[i].Timestamp.Before(items[j].Timestamp) })
		var start *model.Behavior
		for i := range items {
			if items[i].Type == "WebServerSpawnShell" {
				start = &items[i]
				break
			}
		}
		if start == nil {
			continue
		}
		correlated := []model.Behavior{}
		types := map[string]bool{}
		for _, item := range items {
			delta := item.Timestamp.Sub(start.Timestamp)
			if delta >= 0 && delta <= e.window {
				correlated = append(correlated, item)
				types[item.Type] = true
			}
		}
		if !types["WebServerSpawnShell"] || !types["DownloadExecutable"] || !types["ExecuteFromTemp"] || !types["RareExternalConnection"] {
			continue
		}
		evidenceIDs := []string{}
		seen := map[string]bool{}
		score := 0
		behaviorIDs := []string{}
		behaviorTypes := []string{}
		typeSeen := map[string]bool{}
		for _, item := range correlated {
			score += item.RiskScore
			behaviorIDs = append(behaviorIDs, item.BehaviorID)
			if !typeSeen[item.Type] {
				typeSeen[item.Type] = true
				behaviorTypes = append(behaviorTypes, item.Type)
			}
			for _, id := range item.Evidence {
				if !seen[id] {
					seen[id] = true
					evidenceIDs = append(evidenceIDs, id)
				}
			}
		}
		if score > 100 {
			score = 100
		}
		evidenceEvents := []model.RuntimeEvent{}
		for _, event := range events {
			if seen[event.EventID] {
				evidenceEvents = append(evidenceEvents, event)
			}
		}
		sort.Slice(evidenceEvents, func(i, j int) bool { return evidenceEvents[i].Timestamp.Before(evidenceEvents[j].Timestamp) })
		rootName := "web-process"
		rootID := ""
		for _, event := range evidenceEvents {
			if event.EventID == start.Evidence[0] {
				rootName = event.ParentProcess
				rootID = event.ParentProcessEntityID
				break
			}
		}
		startTime := start.Timestamp
		endTime := correlated[len(correlated)-1].Timestamp
		if len(evidenceEvents) > 0 {
			startTime = evidenceEvents[0].Timestamp
			endTime = evidenceEvents[len(evidenceEvents)-1].Timestamp
		}
		result = append(result, model.Incident{IncidentID: "inc-" + shortHash(key+":"+start.Timestamp.Format(time.RFC3339Nano)), Type: "WebRCEPayloadExecution", Severity: severity(score), Risk: severity(score), RiskScore: score, Score: score, Workload: start.Scope.Workload, Namespace: start.Scope.Namespace, ContainerID: start.Scope.ContainerID, HostID: start.Scope.HostID, StartTime: startTime, EndTime: endTime, RootProcess: rootID, RootProcessName: rootName, BehaviorIDs: behaviorIDs, BehaviorTypes: behaviorTypes, Behaviors: correlated, EvidenceEventIDs: evidenceIDs, Correlation: map[string]any{"scope_key": key, "window_seconds": int(e.window.Seconds()), "same_process_tree": true}, Status: "open"})
	}
	return result
}

func severity(score int) string {
	if score >= 80 {
		return "critical"
	}
	if score >= 60 {
		return "high"
	}
	if score >= 30 {
		return "medium"
	}
	return "low"
}
func shortHash(v string) string { sum := sha1.Sum([]byte(v)); return hex.EncodeToString(sum[:])[:10] }
func defaultString(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
