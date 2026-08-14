package collector

import (
	"testing"
	"time"

	"sentinel/internal/sensorabi"
)

type staticEnricher struct{ value ContainerInfo }

func (enricher staticEnricher) Lookup(uint32) ContainerInfo { return enricher.value }

func TestTransformExecEvent(t *testing.T) {
	boot := time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC)
	transformer, err := NewTransformer(HostInfo{HostID: "node-a", BootID: "boot-a", BootTime: boot}, staticEnricher{ContainerInfo{ContainerID: "container-a", Namespace: "default"}})
	if err != nil {
		t.Fatal(err)
	}
	raw := sensorabi.RawEvent{ABIVersion: 1, Size: 496, Type: uint32(sensorabi.EventProcessExec), TimestampNS: uint64(time.Second), ProcessStartNS: uint64(500 * time.Millisecond), PID: 101, TGID: 100, PPID: 10, UID: 1000}
	copy(raw.Arg0[:], "/tmp/payload")
	copy(raw.Arg1[:], "--run")
	copy(raw.ParentComm[:], "bash")
	event, err := transformer.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	process := event["process"].(map[string]any)
	metadata := event["metadata"].(map[string]any)
	container := event["container"].(map[string]any)
	if event["event_type"] != "process_exec" || process["exe"] != "/tmp/payload" || metadata["exec_path"] != "/tmp/payload" || container["container_id"] != "container-a" {
		t.Fatalf("unexpected event: %#v", event)
	}
}

func TestTransformNetworkEvent(t *testing.T) {
	transformer, _ := NewTransformer(HostInfo{HostID: "node-a", BootID: "boot-a", BootTime: time.Unix(0, 0).UTC()}, nil)
	raw := sensorabi.RawEvent{Type: uint32(sensorabi.EventNetworkConnect), TGID: 7, DestinationPort: 443, Protocol: 6, Flags: sensorabi.FlagIPv4}
	copy(raw.DestinationAddr[:4], []byte{8, 8, 8, 8})
	event, err := transformer.Transform(raw)
	if err != nil {
		t.Fatal(err)
	}
	metadata := event["metadata"].(map[string]any)
	if metadata["destination_ip"] != "8.8.8.8" || metadata["destination_port"] != 443 || metadata["protocol"] != "tcp" {
		t.Fatalf("unexpected network metadata: %#v", metadata)
	}
}
