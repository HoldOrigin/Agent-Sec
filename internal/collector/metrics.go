package collector

import (
	"fmt"
	"sync/atomic"

	"sentinel/internal/sensorabi"
)

type Metrics struct {
	Samples      atomic.Uint64
	DecodeErrors atomic.Uint64
	Transformed  atomic.Uint64
	Submitted    atomic.Uint64
	SendErrors   atomic.Uint64
	Batches      atomic.Uint64
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
# HELP sentinel_collector_send_errors_total Failed batch delivery attempts after retries.
# TYPE sentinel_collector_send_errors_total counter
sentinel_collector_send_errors_total %d
# HELP sentinel_collector_batches_total Successfully delivered event batches.
# TYPE sentinel_collector_batches_total counter
sentinel_collector_batches_total %d
# HELP sentinel_ebpf_events_emitted_total Events submitted to the kernel ring buffer.
# TYPE sentinel_ebpf_events_emitted_total counter
sentinel_ebpf_events_emitted_total %d
# HELP sentinel_ebpf_ringbuf_reserve_failed_total Events dropped because ring buffer reservation failed.
# TYPE sentinel_ebpf_ringbuf_reserve_failed_total counter
sentinel_ebpf_ringbuf_reserve_failed_total %d
# HELP sentinel_ebpf_events_filtered_total Events filtered in kernel before reservation.
# TYPE sentinel_ebpf_events_filtered_total counter
sentinel_ebpf_events_filtered_total %d
`, metrics.Samples.Load(), metrics.DecodeErrors.Load(), metrics.Transformed.Load(), metrics.Submitted.Load(), metrics.SendErrors.Load(), metrics.Batches.Load(), kernel.Emitted, kernel.ReserveFailed, kernel.Filtered)
}
