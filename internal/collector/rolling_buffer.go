package collector

import (
	"container/list"
	"encoding/json"
	"sync"
	"time"
)

type rollingEntry struct {
	event      map[string]any
	scope      string
	timestamp  time.Time
	size       int64
	promotable bool
	global     *list.Element
	scoped     *list.Element
}

type RollingBuffer struct {
	mu               sync.Mutex
	ttl              time.Duration
	maxBytes         int64
	maxBytesPerScope int64
	totalBytes       int64
	global           *list.List
	scopes           map[string]*list.List
	scopeBytes       map[string]int64
}

func NewRollingBuffer(ttl time.Duration, maxBytes, maxBytesPerScope int64) *RollingBuffer {
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	if maxBytes <= 0 {
		maxBytes = 128 * 1024 * 1024
	}
	if maxBytesPerScope <= 0 || maxBytesPerScope > maxBytes {
		maxBytesPerScope = minInt64(4*1024*1024, maxBytes)
	}
	return &RollingBuffer{ttl: ttl, maxBytes: maxBytes, maxBytesPerScope: maxBytesPerScope, global: list.New(), scopes: map[string]*list.List{}, scopeBytes: map[string]int64{}}
}

func (buffer *RollingBuffer) Add(event map[string]any, timestamp time.Time, promotable bool) (evicted int) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	evicted += buffer.expireLocked(timestamp)
	scope := eventScopeKey(event)
	data, _ := json.Marshal(event)
	entry := &rollingEntry{event: cloneEvent(event), scope: scope, timestamp: timestamp, size: int64(len(data)), promotable: promotable}
	if entry.size > buffer.maxBytes || entry.size > buffer.maxBytesPerScope {
		return evicted + 1
	}
	scoped := buffer.scopes[scope]
	if scoped == nil {
		scoped = list.New()
		buffer.scopes[scope] = scoped
	}
	entry.global = buffer.global.PushBack(entry)
	entry.scoped = scoped.PushBack(entry)
	buffer.totalBytes += entry.size
	buffer.scopeBytes[scope] += entry.size
	for buffer.scopeBytes[scope] > buffer.maxBytesPerScope {
		buffer.removeLocked(scoped.Front().Value.(*rollingEntry))
		evicted++
	}
	for buffer.totalBytes > buffer.maxBytes && buffer.global.Len() > 0 {
		buffer.removeLocked(buffer.global.Front().Value.(*rollingEntry))
		evicted++
	}
	return evicted
}

func (buffer *RollingBuffer) Promote(scope string, now time.Time) ([]map[string]any, int) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	evicted := buffer.expireLocked(now)
	scoped := buffer.scopes[scope]
	if scoped == nil {
		return nil, evicted
	}
	result := []map[string]any{}
	for element := scoped.Front(); element != nil; {
		next := element.Next()
		entry := element.Value.(*rollingEntry)
		if entry.promotable {
			result = append(result, cloneEvent(entry.event))
			buffer.removeLocked(entry)
		}
		element = next
	}
	return result, evicted
}

func (buffer *RollingBuffer) Snapshot(scope string, now time.Time) []map[string]any {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	buffer.expireLocked(now)
	scoped := buffer.scopes[scope]
	if scoped == nil {
		return nil
	}
	result := make([]map[string]any, 0, scoped.Len())
	for element := scoped.Front(); element != nil; element = element.Next() {
		result = append(result, cloneEvent(element.Value.(*rollingEntry).event))
	}
	return result
}

func (buffer *RollingBuffer) Stats(now time.Time) (bytes int64, entries int, evicted int) {
	buffer.mu.Lock()
	defer buffer.mu.Unlock()
	evicted = buffer.expireLocked(now)
	return buffer.totalBytes, buffer.global.Len(), evicted
}

func (buffer *RollingBuffer) expireLocked(now time.Time) int {
	evicted := 0
	cutoff := now.Add(-buffer.ttl)
	for buffer.global.Len() > 0 {
		entry := buffer.global.Front().Value.(*rollingEntry)
		if entry.timestamp.After(cutoff) {
			break
		}
		buffer.removeLocked(entry)
		evicted++
	}
	return evicted
}

func (buffer *RollingBuffer) removeLocked(entry *rollingEntry) {
	if entry.global == nil {
		return
	}
	buffer.global.Remove(entry.global)
	if scoped := buffer.scopes[entry.scope]; scoped != nil {
		scoped.Remove(entry.scoped)
		buffer.scopeBytes[entry.scope] -= entry.size
		if scoped.Len() == 0 {
			delete(buffer.scopes, entry.scope)
			delete(buffer.scopeBytes, entry.scope)
		}
	}
	buffer.totalBytes -= entry.size
	entry.global = nil
	entry.scoped = nil
}

func cloneEvent(event map[string]any) map[string]any {
	cloned := make(map[string]any, len(event))
	for key, value := range event {
		switch typed := value.(type) {
		case map[string]any:
			cloned[key] = cloneEvent(typed)
		case []string:
			cloned[key] = append([]string(nil), typed...)
		case []any:
			cloned[key] = append([]any(nil), typed...)
		default:
			cloned[key] = value
		}
	}
	return cloned
}

func minInt64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}
