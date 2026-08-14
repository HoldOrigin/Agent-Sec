package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"sentinel/internal/sensorabi"
)

type HostInfo struct {
	HostID   string
	BootID   string
	BootTime time.Time
}

type ContainerInfo struct {
	ContainerID string
	PodUID      string
	Pod         string
	Workload    string
	Namespace   string
}

type Enricher interface {
	Lookup(pid uint32) ContainerInfo
}

type Transformer struct {
	host     HostInfo
	enricher Enricher
}

func NewTransformer(host HostInfo, enricher Enricher) (*Transformer, error) {
	if host.HostID == "" || host.BootID == "" || host.BootTime.IsZero() {
		return nil, fmt.Errorf("host ID, boot ID, and boot time are required")
	}
	return &Transformer{host: host, enricher: enricher}, nil
}

func (transformer *Transformer) Transform(raw sensorabi.RawEvent) (map[string]any, error) {
	eventType, ok := sensorabi.EventTypeName(sensorabi.EventType(raw.Type))
	if !ok {
		return nil, fmt.Errorf("unknown event type %d", raw.Type)
	}
	timestamp := transformer.host.BootTime.Add(time.Duration(raw.TimestampNS)).UTC()
	startTime := transformer.host.BootTime.Add(time.Duration(raw.ProcessStartNS)).UTC()
	executable := sensorabi.CString(raw.Comm[:])
	arg0 := sensorabi.CString(raw.Arg0[:])
	arg1 := sensorabi.CString(raw.Arg1[:])
	argv := []string{}
	if eventType == "process_exec" {
		if arg0 != "" {
			executable = arg0
			argv = append(argv, arg0)
		}
		if arg1 != "" {
			argv = append(argv, arg1)
		}
	}

	metadata := map[string]any{
		"thread_id":         raw.PID,
		"collection_level":  collectionLevelName(raw.CollectionLevel),
		"kernel_event_type": raw.Type,
	}
	switch sensorabi.EventType(raw.Type) {
	case sensorabi.EventProcessExec:
		metadata["exec_path"] = arg0
		metadata["first_seen"] = true
		metadata["image_present"] = false
		metadata["package_source"] = false
	case sensorabi.EventProcessFork:
		metadata["child_comm"] = arg0
	case sensorabi.EventFileOpen, sensorabi.EventFileCreate, sensorabi.EventFileChmod, sensorabi.EventFileUnlink:
		metadata["path"] = arg0
		if sensorabi.EventType(raw.Type) == sensorabi.EventFileCreate {
			metadata["new_file"] = true
		}
		if sensorabi.EventType(raw.Type) == sensorabi.EventFileOpen || sensorabi.EventType(raw.Type) == sensorabi.EventFileCreate {
			metadata["open_flags"] = raw.OperationFlags
		}
		if sensorabi.EventType(raw.Type) == sensorabi.EventFileChmod {
			metadata["mode"] = fmt.Sprintf("%#o", uint32(raw.OperationFlags))
			metadata["executable"] = raw.OperationFlags&0111 != 0
		}
	case sensorabi.EventNetworkConnect:
		if ip := raw.DestinationIP(); ip != nil {
			metadata["destination_ip"] = ip.String()
		}
		metadata["destination_port"] = int(raw.DestinationPort)
		metadata["protocol"] = protocolName(raw.Protocol)
		metadata["baseline_occurrence_30d"] = 0
		metadata["process_exe"] = executable
	}

	container := ContainerInfo{}
	if transformer.enricher != nil {
		container = transformer.enricher.Lookup(raw.TGID)
	}
	processStart := startTime.Format(time.RFC3339Nano)
	if raw.ProcessStartNS == 0 {
		processStart = timestamp.Format(time.RFC3339Nano)
		metadata["process_start_time_inferred"] = true
	}
	event := map[string]any{
		"event_id":   eventID(transformer.host, raw),
		"timestamp":  timestamp.Format(time.RFC3339Nano),
		"event_type": eventType,
		"host": map[string]any{
			"host_id": transformer.host.HostID,
			"boot_id": transformer.host.BootID,
		},
		"process": map[string]any{
			"pid":        raw.TGID,
			"ppid":       raw.PPID,
			"start_time": processStart,
			"exe":        executable,
			"argv":       argv,
			"uid":        raw.UID,
			"gid":        raw.GID,
		},
		"parent_process": sensorabi.CString(raw.ParentComm[:]),
		"container": map[string]any{
			"container_id": container.ContainerID,
			"pod_uid":      container.PodUID,
			"pod":          container.Pod,
			"workload":     container.Workload,
			"namespace":    container.Namespace,
			"cgroup_id":    strconv.FormatUint(raw.CgroupID, 10),
		},
		"metadata": metadata,
	}
	return event, nil
}

func eventID(host HostInfo, event sensorabi.RawEvent) string {
	value := strings.Join([]string{host.HostID, host.BootID, strconv.FormatUint(event.TimestampNS, 10), strconv.FormatUint(uint64(event.TGID), 10), strconv.FormatUint(uint64(event.PID), 10), strconv.FormatUint(uint64(event.Type), 10)}, ":")
	sum := sha256.Sum256([]byte(value))
	return "evt-ebpf-" + hex.EncodeToString(sum[:8])
}

func collectionLevelName(level uint8) string {
	switch level {
	case 1:
		return "WATCH"
	case 2:
		return "INVESTIGATION"
	default:
		return "NORMAL"
	}
}

func protocolName(protocol uint8) string {
	switch protocol {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return "unknown"
	}
}
