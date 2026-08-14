package sensorabi

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestDecode(t *testing.T) {
	if err := ValidateLayout(); err != nil {
		t.Fatal(err)
	}
	want := RawEvent{ABIVersion: ABIVersion, Size: EventSize, Type: uint32(EventNetworkConnect), TGID: 42, DestinationPort: 443, Flags: FlagIPv4}
	copy(want.Comm[:], "curl")
	copy(want.DestinationAddr[:4], []byte{1, 1, 1, 1})
	var payload bytes.Buffer
	if err := binary.Write(&payload, binary.LittleEndian, want); err != nil {
		t.Fatal(err)
	}
	got, err := Decode(payload.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if got.TGID != 42 || CString(got.Comm[:]) != "curl" || got.DestinationIP().String() != "1.1.1.1" {
		t.Fatalf("unexpected decoded event: %+v", got)
	}
}

func TestDecodeRejectsInvalidABI(t *testing.T) {
	event := RawEvent{ABIVersion: 99, Size: EventSize, Type: uint32(EventProcessExec)}
	var payload bytes.Buffer
	_ = binary.Write(&payload, binary.LittleEndian, event)
	if _, err := Decode(payload.Bytes()); err == nil {
		t.Fatal("expected invalid ABI error")
	}
}
