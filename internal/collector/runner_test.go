package collector

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"sentinel/internal/sensorabi"
)

type sliceSource struct {
	samples [][]byte
}

func (source *sliceSource) Read() ([]byte, error) {
	if len(source.samples) == 0 {
		return nil, io.EOF
	}
	sample := source.samples[0]
	source.samples = source.samples[1:]
	return sample, nil
}
func (*sliceSource) Close() error                           { return nil }
func (*sliceSource) Stats() (sensorabi.RuntimeStats, error) { return sensorabi.RuntimeStats{}, nil }

type recordingSender struct {
	batches []int
}

func (sender *recordingSender) Send(_ context.Context, events []map[string]any) error {
	sender.batches = append(sender.batches, len(events))
	return nil
}

func TestRunnerDecodesBatchesAndFlushes(t *testing.T) {
	encode := func(timestamp uint64) []byte {
		event := sensorabi.RawEvent{ABIVersion: sensorabi.ABIVersion, Size: sensorabi.EventSize, Type: uint32(sensorabi.EventProcessExec), TimestampNS: timestamp, TGID: 7}
		copy(event.Arg0[:], "/bin/sh")
		var payload bytes.Buffer
		if err := binary.Write(&payload, binary.LittleEndian, event); err != nil {
			t.Fatal(err)
		}
		return payload.Bytes()
	}
	source := &sliceSource{samples: [][]byte{encode(1), {1, 2, 3}, encode(2), encode(3)}}
	sender := &recordingSender{}
	transformer, _ := NewTransformer(HostInfo{HostID: "host", BootID: "boot", BootTime: time.Unix(1, 0).UTC()}, nil)
	metrics := &Metrics{}
	runner := &Runner{Source: source, Transformer: transformer, Sender: sender, Metrics: metrics, BatchSize: 2, FlushInterval: time.Hour}
	if err := runner.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sender.batches) != 2 || sender.batches[0] != 2 || sender.batches[1] != 1 {
		t.Fatalf("unexpected batches: %#v", sender.batches)
	}
	if metrics.Samples.Load() != 4 || metrics.DecodeErrors.Load() != 1 || metrics.Submitted.Load() != 3 {
		t.Fatalf("unexpected metrics: samples=%d decode=%d submitted=%d", metrics.Samples.Load(), metrics.DecodeErrors.Load(), metrics.Submitted.Load())
	}
}
