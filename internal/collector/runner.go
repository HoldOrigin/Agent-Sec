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
	Source            SampleSource
	Transformer       *Transformer
	Sender            BatchSender
	Router            EventRouter
	Metrics           *Metrics
	BatchSize         int
	FlushInterval     time.Duration
	HighFlushInterval time.Duration
	Logger            *slog.Logger
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
	if runner.HighFlushInterval <= 0 {
		runner.HighFlushInterval = 100 * time.Millisecond
	}
	if runner.Logger == nil {
		runner.Logger = slog.Default()
	}
	events := make(chan map[string]any, runner.BatchSize*4)
	readErrors := make(chan error, 1)
	go runner.readLoop(ctx, events, readErrors)
	errorChannel := (<-chan error)(readErrors)
	var sourceErr error

	normalTicker := time.NewTicker(runner.FlushInterval)
	highTicker := time.NewTicker(runner.HighFlushInterval)
	aggregateTicker := time.NewTicker(time.Second)
	defer normalTicker.Stop()
	defer highTicker.Stop()
	defer aggregateTicker.Stop()
	highBatch := make([]map[string]any, 0, runner.BatchSize)
	normalBatch := make([]map[string]any, 0, runner.BatchSize)
	flush := func(flushCtx context.Context, batch *[]map[string]any, priority UploadPriority) error {
		if len(*batch) == 0 {
			return nil
		}
		if err := runner.Sender.Send(flushCtx, *batch); err != nil {
			runner.Metrics.SendErrors.Add(1)
			return err
		}
		count := uint64(len(*batch))
		runner.Metrics.Submitted.Add(count)
		if priority == PriorityHigh {
			runner.Metrics.HighPrioritySubmitted.Add(count)
		} else {
			runner.Metrics.NormalSubmitted.Add(count)
		}
		runner.Metrics.Batches.Add(1)
		*batch = (*batch)[:0]
		return nil
	}
	enqueue := func(routeCtx context.Context, routed []RoutedEvent) error {
		for _, item := range routed {
			batch := &normalBatch
			priority := item.Priority
			if priority == PriorityHigh {
				batch = &highBatch
			}
			*batch = append(*batch, item.Event)
			if len(*batch) >= runner.BatchSize {
				if err := flush(routeCtx, batch, priority); err != nil {
					return err
				}
			}
		}
		return nil
	}
	flushAll := func(flushCtx context.Context, force bool) error {
		if runner.Router != nil {
			if err := enqueue(flushCtx, runner.Router.Flush(time.Now().UTC(), force)); err != nil {
				return err
			}
		}
		if err := flush(flushCtx, &highBatch, PriorityHigh); err != nil {
			return err
		}
		return flush(flushCtx, &normalBatch, PriorityNormal)
	}
	for {
		select {
		case event, ok := <-events:
			runner.Metrics.InputQueueDepth.Store(int64(len(events)))
			if !ok {
				if errorChannel != nil {
					select {
					case sourceErr = <-errorChannel:
					default:
					}
				}
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				err := flushAll(shutdownCtx, true)
				cancel()
				if err != nil {
					return err
				}
				if sourceErr != nil && ctx.Err() == nil && !errors.Is(sourceErr, io.EOF) {
					return fmt.Errorf("read ring buffer: %w", sourceErr)
				}
				return nil
			}
			routed := []RoutedEvent{{Event: event, Priority: PriorityNormal}}
			if runner.Router != nil {
				routed = runner.Router.Process(event, time.Now().UTC())
			}
			if err := enqueue(ctx, routed); err != nil {
				return err
			}
		case sourceErr = <-errorChannel:
			errorChannel = nil
		case now := <-aggregateTicker.C:
			if runner.Router != nil {
				if err := enqueue(ctx, runner.Router.Flush(now.UTC(), false)); err != nil {
					return err
				}
			}
		case <-highTicker.C:
			if err := flush(ctx, &highBatch, PriorityHigh); err != nil {
				return err
			}
		case <-normalTicker.C:
			if err := flush(ctx, &normalBatch, PriorityNormal); err != nil {
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
			runner.Metrics.InputQueueDepth.Store(int64(len(events)))
		case <-ctx.Done():
			return
		}
	}
}
