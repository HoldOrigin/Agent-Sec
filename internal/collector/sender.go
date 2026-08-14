package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type BatchSender interface {
	Send(ctx context.Context, events []map[string]any) error
}

type HTTPSender struct {
	endpoint string
	client   *http.Client
	retries  int
}

func NewHTTPSender(baseURL string, timeout time.Duration, retries int) *HTTPSender {
	return &HTTPSender{
		endpoint: strings.TrimRight(baseURL, "/") + "/api/events/batch",
		client:   &http.Client{Timeout: timeout},
		retries:  retries,
	}
}

func (sender *HTTPSender) Send(ctx context.Context, events []map[string]any) error {
	if len(events) == 0 {
		return nil
	}
	payload, err := json.Marshal(map[string]any{"reset": false, "events": events})
	if err != nil {
		return fmt.Errorf("encode event batch: %w", err)
	}
	var lastErr error
	for attempt := 0; attempt <= sender.retries; attempt++ {
		request, requestErr := http.NewRequestWithContext(ctx, http.MethodPost, sender.endpoint, bytes.NewReader(payload))
		if requestErr != nil {
			return fmt.Errorf("create event request: %w", requestErr)
		}
		request.Header.Set("content-type", "application/json")
		response, requestErr := sender.client.Do(request)
		if requestErr == nil {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 64*1024))
			response.Body.Close()
			if readErr == nil && response.StatusCode >= 200 && response.StatusCode < 300 {
				return nil
			}
			if readErr != nil {
				lastErr = fmt.Errorf("read collector response: %w", readErr)
			} else {
				lastErr = fmt.Errorf("collector API returned %s: %s", response.Status, strings.TrimSpace(string(body)))
			}
		} else {
			lastErr = requestErr
		}
		if attempt == sender.retries {
			break
		}
		delay := time.Duration(1<<attempt) * 100 * time.Millisecond
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return fmt.Errorf("deliver event batch: %w", lastErr)
}
