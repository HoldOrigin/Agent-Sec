package graph

import (
	"fmt"
	"strings"

	"sentinel/internal/model"
)

func Build(events []model.RuntimeEvent) model.Graph {
	nodes := map[string]model.GraphNode{}
	edges := []model.GraphEdge{}
	edgeSeen := map[string]bool{}
	addNode := func(id, kind, label string, metadata map[string]any) {
		if id != "" {
			if _, ok := nodes[id]; !ok {
				nodes[id] = model.GraphNode{ID: id, Type: kind, Label: label, Metadata: metadata}
			}
		}
	}
	addEdge := func(source, target, relation, evidence string) {
		key := source + "|" + target + "|" + relation
		if source != "" && target != "" && !edgeSeen[key] {
			edgeSeen[key] = true
			edges = append(edges, model.GraphEdge{Source: source, Target: target, Relation: relation, EvidenceEventID: evidence})
		}
	}
	for _, event := range events {
		processID := event.ProcessEntityID
		parentID := event.ParentProcessEntityID
		addNode(processID, "process", event.Process, map[string]any{"pid": event.PID, "cmdline": event.Cmdline, "exe": event.Exe})
		if event.ParentProcess != "" && event.PPID > 0 {
			addNode(parentID, "process", event.ParentProcess, map[string]any{"pid": event.PPID})
			addEdge(parentID, processID, "PARENT_OF", event.EventID)
		}
		if event.ContainerID != "" {
			containerID := "container:" + event.ContainerID
			label := event.Pod
			if label == "" {
				label = event.ContainerID
			}
			addNode(containerID, "container", label, map[string]any{"namespace": event.Namespace})
			addEdge(processID, containerID, "RUN_IN", event.EventID)
			if event.Workload != "" {
				workloadID := fmt.Sprintf("workload:%s:%s", defaultString(event.Namespace, "default"), event.Workload)
				addNode(workloadID, "workload", event.Workload, map[string]any{"namespace": event.Namespace})
				addEdge(containerID, workloadID, "BELONG_TO", event.EventID)
			}
		}
		path := metaString(event, "path")
		if path == "" {
			path = metaString(event, "exec_path")
		}
		if path != "" {
			fileID := "file:" + path
			addNode(fileID, "file", path, nil)
			relation := "EXEC"
			if event.Type != "process_exec" {
				relation = strings.ToUpper(strings.TrimPrefix(event.Type, "file_"))
			}
			addEdge(processID, fileID, relation, event.EventID)
		}
		destination := metaString(event, "domain")
		if destination == "" {
			destination = metaString(event, "destination_ip")
		}
		if destination != "" {
			port := metaInt(event, "destination_port")
			networkID := fmt.Sprintf("network:%s:%d", destination, port)
			label := destination
			if port > 0 {
				label = fmt.Sprintf("%s:%d", destination, port)
			}
			addNode(networkID, "network", label, nil)
			addEdge(processID, networkID, "CONNECT", event.EventID)
			if downloadPath := metaString(event, "download_path"); downloadPath != "" {
				fileID := "file:" + downloadPath
				addNode(fileID, "file", downloadPath, nil)
				addEdge(networkID, fileID, "DOWNLOAD", event.EventID)
			}
		}
	}
	resultNodes := make([]model.GraphNode, 0, len(nodes))
	for _, node := range nodes {
		resultNodes = append(resultNodes, node)
	}
	return model.Graph{Nodes: resultNodes, Edges: edges}
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
func defaultString(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
