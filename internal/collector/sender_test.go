package collector

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPSenderPostsBatch(t *testing.T) {
	var received int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/events/batch" || request.Method != http.MethodPost {
			t.Fatalf("unexpected request: %s %s", request.Method, request.URL.Path)
		}
		body := request.Body
		if request.Header.Get("content-encoding") == "gzip" {
			reader, err := gzip.NewReader(request.Body)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			body = reader
		}
		var payload struct {
			Events []map[string]any `json:"events"`
		}
		if err := json.NewDecoder(body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		received = len(payload.Events)
		writer.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	sender := NewHTTPSender(server.URL, time.Second, 0)
	if err := sender.Send(context.Background(), []map[string]any{{"event_id": "one"}, {"event_id": "two"}}); err != nil {
		t.Fatal(err)
	}
	if received != 2 {
		t.Fatalf("received %d events, want 2", received)
	}
}

func TestHTTPSenderCompressesLargeBatch(t *testing.T) {
	compressed := false
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		compressed = request.Header.Get("content-encoding") == "gzip"
		writer.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	events := make([]map[string]any, 20)
	for index := range events {
		events[index] = map[string]any{"event_id": "event", "payload": string(make([]byte, 256))}
	}
	metrics := &Metrics{}
	if err := NewHTTPSender(server.URL, time.Second, 0, metrics).Send(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	if !compressed {
		t.Fatal("expected large batch to use gzip content encoding")
	}
	if metrics.UploadWireBytes.Load() >= metrics.UploadPayloadBytes.Load() {
		t.Fatalf("wire bytes=%d payload bytes=%d", metrics.UploadWireBytes.Load(), metrics.UploadPayloadBytes.Load())
	}
}
