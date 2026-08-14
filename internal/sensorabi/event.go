package sensorabi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	ABIVersion = 1
	EventSize  = 496
)

type EventType uint32

const (
	EventProcessFork    EventType = 1
	EventProcessExec    EventType = 2
	EventProcessExit    EventType = 3
	EventFileOpen       EventType = 10
	EventFileCreate     EventType = 11
	EventFileChmod      EventType = 12
	EventFileUnlink     EventType = 13
	EventNetworkConnect EventType = 20
)

const (
	FlagIPv4 uint16 = 1 << iota
	FlagIPv6
	FlagTruncated
)

// RawEvent mirrors sensor/ebpf/runtime.h. binary.Size(RawEvent{}) must remain
// EventSize; fields are fixed-width and ABI changes are append-only.
type RawEvent struct {
	ABIVersion      uint16
	Size            uint16
	Type            uint32
	TimestampNS     uint64
	CgroupID        uint64
	ProcessStartNS  uint64
	PID             uint32
	TGID            uint32
	PPID            uint32
	UID             uint32
	GID             uint32
	OperationFlags  int32
	AddressFamily   uint16
	DestinationPort uint16
	Protocol        uint8
	CollectionLevel uint8
	Flags           uint16
	DestinationAddr [16]byte
	Comm            [16]byte
	ParentComm      [16]byte
	Arg0            [256]byte
	Arg1            [128]byte
}

type RuntimeStats struct {
	Emitted       uint64
	ReserveFailed uint64
	Filtered      uint64
}

func Decode(sample []byte) (RawEvent, error) {
	if len(sample) < EventSize {
		return RawEvent{}, fmt.Errorf("ring buffer sample is %d bytes, want at least %d", len(sample), EventSize)
	}
	var event RawEvent
	if err := binary.Read(bytes.NewReader(sample[:EventSize]), binary.LittleEndian, &event); err != nil {
		return RawEvent{}, fmt.Errorf("decode runtime event: %w", err)
	}
	if event.ABIVersion != ABIVersion {
		return RawEvent{}, fmt.Errorf("unsupported runtime event ABI %d", event.ABIVersion)
	}
	if event.Size != EventSize {
		return RawEvent{}, fmt.Errorf("runtime event size is %d, want %d", event.Size, EventSize)
	}
	if _, ok := EventTypeName(EventType(event.Type)); !ok {
		return RawEvent{}, fmt.Errorf("unknown runtime event type %d", event.Type)
	}
	return event, nil
}

func EventTypeName(eventType EventType) (string, bool) {
	switch eventType {
	case EventProcessFork:
		return "process_fork", true
	case EventProcessExec:
		return "process_exec", true
	case EventProcessExit:
		return "process_exit", true
	case EventFileOpen:
		return "file_open", true
	case EventFileCreate:
		return "file_create", true
	case EventFileChmod:
		return "file_chmod", true
	case EventFileUnlink:
		return "file_unlink", true
	case EventNetworkConnect:
		return "network_connect", true
	default:
		return "", false
	}
}

func CString(value []byte) string {
	if index := bytes.IndexByte(value, 0); index >= 0 {
		value = value[:index]
	}
	return string(value)
}

func (event RawEvent) DestinationIP() net.IP {
	if event.Flags&FlagIPv4 != 0 {
		return net.IPv4(event.DestinationAddr[0], event.DestinationAddr[1], event.DestinationAddr[2], event.DestinationAddr[3])
	}
	if event.Flags&FlagIPv6 != 0 {
		return net.IP(append([]byte(nil), event.DestinationAddr[:]...))
	}
	return nil
}

func ValidateLayout() error {
	if size := binary.Size(RawEvent{}); size != EventSize {
		return fmt.Errorf("Go runtime event ABI size is %d, want %d", size, EventSize)
	}
	if binary.Size(RuntimeStats{}) != 24 {
		return errors.New("Go runtime stats ABI size changed")
	}
	return nil
}
