package collector

import (
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
		var payload struct {
			Events []map[string]any `json:"events"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
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
