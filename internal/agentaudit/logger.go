package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"sentinel/internal/agenttools"
)

type Logger struct {
	Terminal *slog.Logger
	Path     string
	mu       sync.Mutex
	sequence uint64
}

func (l *Logger) Log(event string, details map[string]any) error {
	return l.record(map[string]any{"event": event, "details": details})
}

func (l *Logger) Write(_ context.Context, record tools.AuditRecord) error {
	var details any
	_ = json.Unmarshal(record.Details, &details)
	return l.record(map[string]any{"event": record.Event, "call_id": record.CallID, "tool": record.Tool, "status": record.Status, "details": details})
}

func (l *Logger) record(entry map[string]any) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sequence++
	entry["sequence"] = l.sequence
	entry["recorded_at"] = time.Now().UTC()
	encoded, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if l.Terminal != nil {
		l.Terminal.Info("调查审计", "entry", string(encoded))
	}
	if l.Path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(l.Path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(l.Path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		return err
	}
	return file.Sync()
}
