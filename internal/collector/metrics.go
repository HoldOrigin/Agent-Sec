package collector

import (
	"fmt"
	"sync/atomic"

	"sentinel/internal/sensorabi"
)

type Metrics struct {
	Samples               atomic.Uint64
	DecodeErrors          atomic.Uint64
	Transformed           atomic.Uint64
	Submitted             atomic.Uint64
	HighPrioritySubmitted atomic.Uint64
	NormalSubmitted       atomic.Uint64
	SendErrors            atomic.Uint64
	Batches               atomic.Uint64
	UploadAlways          atomic.Uint64
	LocalAlerts           atomic.Uint64
	BlacklistHits         atomic.Uint64
	WhitelistHits         atomic.Uint64
	RuleReloads           atomic.Uint64
	RuleReloadErrors      atomic.Uint64
	RuleEvaluationErrors  atomic.Uint64
	UploadOnAlertBuffered atomic.Uint64
	UploadLocalOnly       atomic.Uint64
	LocalOnlySummaries    atomic.Uint64
	AggregateInput        atomic.Uint64
	AggregateOutput       atomic.Uint64
	ContextPromoted       atomic.Uint64
	BufferEvicted         atomic.Uint64
	BufferBytes           atomic.Int64
	BufferEntries         atomic.Int64
	AggregateKeys         atomic.Int64
	ActiveAlertScopes     atomic.Int64
	InputQueueDepth       atomic.Int64
	UploadPayloadBytes    atomic.Uint64
	UploadWireBytes       atomic.Uint64
}

func (metrics *Metrics) Prometheus(kernel sensorabi.RuntimeStats) string {
	return fmt.Sprintf(`# HELP sentinel_collector_samples_total Ring buffer samples read by userspace.
# TYPE sentinel_collector_samples_total counter
sentinel_collector_samples_total %d
# HELP sentinel_collector_decode_errors_total Samples rejected by ABI validation or decoding.
# TYPE sentinel_collector_decode_errors_total counter
sentinel_collector_decode_errors_total %d
# HELP sentinel_collector_events_transformed_total Kernel samples normalized into RuntimeEvent inputs.
# TYPE sentinel_collector_events_transformed_total counter
sentinel_collector_events_transformed_total %d
# HELP sentinel_collector_events_submitted_total RuntimeEvent inputs accepted by the upstream API.
# TYPE sentinel_collector_events_submitted_total counter
sentinel_collector_events_submitted_total %d
# HELP sentinel_collector_high_priority_submitted_total High-priority events delivered to the upstream API.
# TYPE sentinel_collector_high_priority_submitted_total counter
sentinel_collector_high_priority_submitted_total %d
# HELP sentinel_collector_normal_submitted_total Normal-priority aggregate events delivered to the upstream API.
# TYPE sentinel_collector_normal_submitted_total counter
sentinel_collector_normal_submitted_total %d
# HELP sentinel_collector_send_errors_total Failed batch delivery attempts after retries.
# TYPE sentinel_collector_send_errors_total counter
sentinel_collector_send_errors_total %d
# HELP sentinel_collector_batches_total Successfully delivered event batches.
# TYPE sentinel_collector_batches_total counter
sentinel_collector_batches_total %d
# HELP sentinel_collector_upload_decisions_total Events classified by upload mode.
# TYPE sentinel_collector_upload_decisions_total counter
sentinel_collector_upload_decisions_total{mode="always"} %d
sentinel_collector_upload_decisions_total{mode="on_alert"} %d
sentinel_collector_upload_decisions_total{mode="aggregate"} %d
sentinel_collector_upload_decisions_total{mode="local_only"} %d
# HELP sentinel_collector_local_only_summaries_total LOCAL_ONLY aggregate summaries retained in the rolling buffer.
# TYPE sentinel_collector_local_only_summaries_total counter
sentinel_collector_local_only_summaries_total %d
# HELP sentinel_collector_local_alerts_total Events promoted by the local DetectionPolicy.
# TYPE sentinel_collector_local_alerts_total counter
sentinel_collector_local_alerts_total %d
# HELP sentinel_collector_detection_rule_hits_total CEL detection rule matches by rule kind.
# TYPE sentinel_collector_detection_rule_hits_total counter
sentinel_collector_detection_rule_hits_total{kind="blacklist"} %d
sentinel_collector_detection_rule_hits_total{kind="whitelist"} %d
# HELP sentinel_collector_detection_rule_reloads_total Successful atomic CEL rule snapshot reloads.
# TYPE sentinel_collector_detection_rule_reloads_total counter
sentinel_collector_detection_rule_reloads_total %d
# HELP sentinel_collector_detection_rule_reload_errors_total Rejected CEL rule snapshot reloads.
# TYPE sentinel_collector_detection_rule_reload_errors_total counter
sentinel_collector_detection_rule_reload_errors_total %d
# HELP sentinel_collector_detection_rule_evaluation_errors_total CEL evaluation errors caused by incompatible event data.
# TYPE sentinel_collector_detection_rule_evaluation_errors_total counter
sentinel_collector_detection_rule_evaluation_errors_total %d
# HELP sentinel_collector_aggregate_input_total Events folded into user-space aggregate buckets.
# TYPE sentinel_collector_aggregate_input_total counter
sentinel_collector_aggregate_input_total %d
# HELP sentinel_collector_aggregate_output_total Aggregate meta-events emitted for upload.
# TYPE sentinel_collector_aggregate_output_total counter
sentinel_collector_aggregate_output_total %d
# HELP sentinel_collector_context_promoted_total Buffered events promoted after a local alert.
# TYPE sentinel_collector_context_promoted_total counter
sentinel_collector_context_promoted_total %d
# HELP sentinel_collector_buffer_evicted_total Events evicted by TTL or byte limits.
# TYPE sentinel_collector_buffer_evicted_total counter
sentinel_collector_buffer_evicted_total %d
# HELP sentinel_collector_buffer_bytes Current estimated JSON bytes retained in the rolling buffer.
# TYPE sentinel_collector_buffer_bytes gauge
sentinel_collector_buffer_bytes %d
# HELP sentinel_collector_buffer_entries Current events retained in the rolling buffer.
# TYPE sentinel_collector_buffer_entries gauge
sentinel_collector_buffer_entries %d
# HELP sentinel_collector_aggregate_keys Current active aggregation keys.
# TYPE sentinel_collector_aggregate_keys gauge
sentinel_collector_aggregate_keys %d
# HELP sentinel_collector_active_alert_scopes Current scopes in the post-alert upload window.
# TYPE sentinel_collector_active_alert_scopes gauge
sentinel_collector_active_alert_scopes %d
# HELP sentinel_collector_input_queue_depth Current transformed-event input queue depth.
# TYPE sentinel_collector_input_queue_depth gauge
sentinel_collector_input_queue_depth %d
# HELP sentinel_collector_upload_payload_bytes_total Uncompressed JSON bytes in attempted HTTP batches.
# TYPE sentinel_collector_upload_payload_bytes_total counter
sentinel_collector_upload_payload_bytes_total %d
# HELP sentinel_collector_upload_wire_bytes_total Compressed or raw body bytes in attempted HTTP batches.
# TYPE sentinel_collector_upload_wire_bytes_total counter
sentinel_collector_upload_wire_bytes_total %d
# HELP sentinel_ebpf_events_emitted_total Events submitted to the kernel ring buffer.
# TYPE sentinel_ebpf_events_emitted_total counter
sentinel_ebpf_events_emitted_total %d
# HELP sentinel_ebpf_ringbuf_reserve_failed_total Events dropped because ring buffer reservation failed.
# TYPE sentinel_ebpf_ringbuf_reserve_failed_total counter
sentinel_ebpf_ringbuf_reserve_failed_total %d
# HELP sentinel_ebpf_events_filtered_total Events filtered in kernel before reservation.
# TYPE sentinel_ebpf_events_filtered_total counter
sentinel_ebpf_events_filtered_total %d
`, metrics.Samples.Load(), metrics.DecodeErrors.Load(), metrics.Transformed.Load(), metrics.Submitted.Load(), metrics.HighPrioritySubmitted.Load(), metrics.NormalSubmitted.Load(), metrics.SendErrors.Load(), metrics.Batches.Load(), metrics.UploadAlways.Load(), metrics.UploadOnAlertBuffered.Load(), metrics.AggregateInput.Load(), metrics.UploadLocalOnly.Load(), metrics.LocalOnlySummaries.Load(), metrics.LocalAlerts.Load(), metrics.BlacklistHits.Load(), metrics.WhitelistHits.Load(), metrics.RuleReloads.Load(), metrics.RuleReloadErrors.Load(), metrics.RuleEvaluationErrors.Load(), metrics.AggregateInput.Load(), metrics.AggregateOutput.Load(), metrics.ContextPromoted.Load(), metrics.BufferEvicted.Load(), metrics.BufferBytes.Load(), metrics.BufferEntries.Load(), metrics.AggregateKeys.Load(), metrics.ActiveAlertScopes.Load(), metrics.InputQueueDepth.Load(), metrics.UploadPayloadBytes.Load(), metrics.UploadWireBytes.Load(), kernel.Emitted, kernel.ReserveFailed, kernel.Filtered)
}
