package collector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"sentinel/internal/sensorabi"
)

type SampleSource interface {
	Read() ([]byte, error)
	Close() error
	Stats() (sensorabi.RuntimeStats, error)
}

type Runner struct {
	Source        SampleSource
	Transformer   *Transformer
	Sender        BatchSender
	Metrics       *Metrics
	BatchSize     int
	FlushInterval time.Duration
	Logger        *slog.Logger
}

func (runner *Runner) Run(ctx context.Context) error {
	if runner.Source == nil || runner.Transformer == nil || runner.Sender == nil || runner.Metrics == nil {
		return errors.New("collector runner dependencies are required")
	}
	if runner.BatchSize <= 0 {
		runner.BatchSize = 100
	}
	if runner.FlushInterval <= 0 {
		runner.FlushInterval = 500 * time.Millisecond
	}
	if runner.Logger == nil {
		runner.Logger = slog.Default()
	}
	events := make(chan map[string]any, runner.BatchSize*4)
	readErrors := make(chan error, 1)
	go runner.readLoop(ctx, events, readErrors)
	errorChannel := (<-chan error)(readErrors)
	var sourceErr error

	ticker := time.NewTicker(runner.FlushInterval)
	defer ticker.Stop()
	batch := make([]map[string]any, 0, runner.BatchSize)
	flush := func(flushCtx context.Context) error {
		if len(batch) == 0 {
			return nil
		}
		if err := runner.Sender.Send(flushCtx, batch); err != nil {
			runner.Metrics.SendErrors.Add(1)
			return err
		}
		runner.Metrics.Submitted.Add(uint64(len(batch)))
		runner.Metrics.Batches.Add(1)
		batch = batch[:0]
		return nil
	}
	for {
		select {
		case event, ok := <-events:
			if !ok {
				if errorChannel != nil {
					select {
					case sourceErr = <-errorChannel:
					default:
					}
				}
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				err := flush(shutdownCtx)
				cancel()
				if err != nil {
					return err
				}
				if sourceErr != nil && ctx.Err() == nil && !errors.Is(sourceErr, io.EOF) {
					return fmt.Errorf("read ring buffer: %w", sourceErr)
				}
				return nil
			}
			batch = append(batch, event)
			if len(batch) >= runner.BatchSize {
				if err := flush(ctx); err != nil {
					return err
				}
			}
		case sourceErr = <-errorChannel:
			errorChannel = nil
		case <-ticker.C:
			if err := flush(ctx); err != nil {
				return err
			}
		case <-ctx.Done():
			_ = runner.Source.Close()
		}
	}
}

func (runner *Runner) readLoop(ctx context.Context, events chan<- map[string]any, readErrors chan<- error) {
	defer close(events)
	for {
		sample, err := runner.Source.Read()
		if err != nil {
			readErrors <- err
			return
		}
		runner.Metrics.Samples.Add(1)
		raw, err := sensorabi.Decode(sample)
		if err != nil {
			runner.Metrics.DecodeErrors.Add(1)
			runner.Logger.Warn("discarding invalid ring buffer sample", "error", err)
			continue
		}
		event, err := runner.Transformer.Transform(raw)
		if err != nil {
			runner.Metrics.DecodeErrors.Add(1)
			runner.Logger.Warn("discarding untransformable ring buffer sample", "error", err)
			continue
		}
		runner.Metrics.Transformed.Add(1)
		select {
		case events <- event:
		case <-ctx.Done():
			return
		}
	}
}
