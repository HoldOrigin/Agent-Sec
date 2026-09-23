package llm

import (
	"context"
	"time"
)

type RetryingCaller struct {
	Next        Caller
	MaxAttempts int
	BaseDelay   time.Duration
}

func (r RetryingCaller) Call(ctx context.Context, model, phase, rolePrompt string, contract, input, output any) error {
	attempts := r.MaxAttempts
	if attempts <= 0 {
		attempts = 3
	}
	delay := r.BaseDelay
	if delay <= 0 {
		delay = 250 * time.Millisecond
	}
	var last error
	for attempt := 1; attempt <= attempts; attempt++ {
		if err := r.Next.Call(ctx, model, phase, rolePrompt, contract, input, output); err != nil {
			last = err
			retryable, ok := err.(interface{ Retryable() bool })
			if !ok || !retryable.Retryable() || attempt == attempts {
				return err
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
			delay *= 2
			continue
		}
		return nil
	}
	return last
}
