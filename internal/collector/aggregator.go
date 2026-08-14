package collector

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"sync"
	"time"
)

type aggregateBucket struct {
	key        string
	represent  map[string]any
	count      uint64
	firstSeen  time.Time
	lastSeen   time.Time
	orderEntry *list.Element
}

type EventAggregator struct {
	mu      sync.Mutex
	window  time.Duration
	maxKeys int
	buckets map[string]*aggregateBucket
	order   *list.List
}

func NewEventAggregator(window time.Duration, maxKeys int) *EventAggregator {
	if window <= 0 {
		window = time.Minute
	}
	if maxKeys <= 0 {
		maxKeys = 16384
	}
	return &EventAggregator{window: window, maxKeys: maxKeys, buckets: map[string]*aggregateBucket{}, order: list.New()}
}

func (aggregator *EventAggregator) Add(event map[string]any, now time.Time) []map[string]any {
	aggregator.mu.Lock()
	defer aggregator.mu.Unlock()
	key := eventAggregationKey(event)
	if bucket := aggregator.buckets[key]; bucket != nil {
		if now.Sub(bucket.firstSeen) < aggregator.window {
			bucket.count++
			bucket.lastSeen = now
			aggregator.order.MoveToBack(bucket.orderEntry)
			return nil
		}
		result := []map[string]any{aggregator.emitLocked(bucket)}
		aggregator.removeLocked(bucket)
		aggregator.addLocked(key, event, now)
		return result
	}
	result := []map[string]any{}
	if len(aggregator.buckets) >= aggregator.maxKeys {
		oldest := aggregator.order.Front().Value.(*aggregateBucket)
		result = append(result, aggregator.emitLocked(oldest))
		aggregator.removeLocked(oldest)
	}
	aggregator.addLocked(key, event, now)
	return result
}

func (aggregator *EventAggregator) Flush(now time.Time, force bool) []map[string]any {
	aggregator.mu.Lock()
	defer aggregator.mu.Unlock()
	result := []map[string]any{}
	for element := aggregator.order.Front(); element != nil; {
		next := element.Next()
		bucket := element.Value.(*aggregateBucket)
		if force || now.Sub(bucket.firstSeen) >= aggregator.window {
			result = append(result, aggregator.emitLocked(bucket))
			aggregator.removeLocked(bucket)
		}
		element = next
	}
	return result
}

func (aggregator *EventAggregator) Len() int {
	aggregator.mu.Lock()
	defer aggregator.mu.Unlock()
	return len(aggregator.buckets)
}

func (aggregator *EventAggregator) addLocked(key string, event map[string]any, now time.Time) {
	bucket := &aggregateBucket{key: key, represent: cloneEvent(event), count: 1, firstSeen: now, lastSeen: now}
	bucket.orderEntry = aggregator.order.PushBack(bucket)
	aggregator.buckets[key] = bucket
}

func (aggregator *EventAggregator) emitLocked(bucket *aggregateBucket) map[string]any {
	event := cloneEvent(bucket.represent)
	metadata := eventMap(event, "metadata")
	metadata["aggregate"] = true
	metadata["aggregate_count"] = bucket.count
	metadata["aggregate_window"] = aggregator.window.String()
	metadata["aggregate_first_seen"] = bucket.firstSeen.UTC().Format(time.RFC3339Nano)
	metadata["aggregate_last_seen"] = bucket.lastSeen.UTC().Format(time.RFC3339Nano)
	metadata["upload_mode"] = string(UploadAggregate)
	metadata["upload_priority"] = string(PriorityNormal)
	event["metadata"] = metadata
	sum := sha256.Sum256([]byte(bucket.key + "|" + strconv.FormatInt(bucket.firstSeen.UnixNano(), 10) + "|" + strconv.FormatInt(bucket.lastSeen.UnixNano(), 10)))
	event["event_id"] = "evt-aggregate-" + hex.EncodeToString(sum[:8])
	event["timestamp"] = bucket.lastSeen.UTC().Format(time.RFC3339Nano)
	return event
}

func (aggregator *EventAggregator) removeLocked(bucket *aggregateBucket) {
	delete(aggregator.buckets, bucket.key)
	aggregator.order.Remove(bucket.orderEntry)
}
