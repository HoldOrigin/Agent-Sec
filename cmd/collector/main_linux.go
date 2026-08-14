//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"sentinel/internal/collector"
	"sentinel/internal/sensorabi"
)

func main() {
	var objectPath string
	var serverURL string
	var metricsAddress string
	var batchSize int
	var flushInterval time.Duration
	var excludePIDs string
	var excludeUIDs string
	var excludeCgroups string
	var watchCgroups string
	var investigationCgroups string
	flag.StringVar(&objectPath, "object", "sensor/ebpf/runtime.bpf.o", "compiled CO-RE eBPF object")
	flag.StringVar(&serverURL, "server", "http://127.0.0.1:8080", "Sentinel server base URL")
	flag.StringVar(&metricsAddress, "metrics", "127.0.0.1:9091", "collector metrics listen address; empty disables it")
	flag.IntVar(&batchSize, "batch-size", 100, "maximum events per API batch")
	flag.DurationVar(&flushInterval, "flush-interval", 500*time.Millisecond, "maximum event batch delay")
	flag.StringVar(&excludePIDs, "exclude-pids", "", "comma-separated process IDs to filter")
	flag.StringVar(&excludeUIDs, "exclude-uids", "", "comma-separated user IDs to filter")
	flag.StringVar(&excludeCgroups, "exclude-cgroups", "", "comma-separated numeric cgroup IDs to filter")
	flag.StringVar(&watchCgroups, "watch-cgroups", "", "comma-separated cgroup IDs to collect at WATCH level")
	flag.StringVar(&investigationCgroups, "investigation-cgroups", "", "comma-separated cgroup IDs to collect at INVESTIGATION level")
	flag.Parse()
	if err := sensorabi.ValidateLayout(); err != nil {
		slog.Error("invalid sensor ABI", "error", err)
		os.Exit(1)
	}
	host, err := collector.ReadHostInfo()
	if err != nil {
		slog.Error("read host identity", "error", err)
		os.Exit(1)
	}
	pids, err := parseUint32List(excludePIDs)
	if err != nil {
		slog.Error("parse excluded PIDs", "error", err)
		os.Exit(2)
	}
	uids, err := parseUint32List(excludeUIDs)
	if err != nil {
		slog.Error("parse excluded UIDs", "error", err)
		os.Exit(2)
	}
	cgroups, err := parseUint64List(excludeCgroups)
	if err != nil {
		slog.Error("parse excluded cgroups", "error", err)
		os.Exit(2)
	}
	levels := map[uint64]uint8{}
	watch, err := parseUint64List(watchCgroups)
	if err != nil {
		slog.Error("parse WATCH cgroups", "error", err)
		os.Exit(2)
	}
	for _, cgroupID := range watch {
		levels[cgroupID] = 1
	}
	investigation, err := parseUint64List(investigationCgroups)
	if err != nil {
		slog.Error("parse INVESTIGATION cgroups", "error", err)
		os.Exit(2)
	}
	for _, cgroupID := range investigation {
		levels[cgroupID] = 2
	}
	source, err := collector.OpenLinuxSource(collector.SourceConfig{ObjectPath: objectPath, ExcludePIDs: pids, ExcludeUIDs: uids, ExcludeCgroups: cgroups, CollectionLevels: levels})
	if err != nil {
		slog.Error("open eBPF sensor", "error", err)
		os.Exit(1)
	}
	defer source.Close()
	transformer, err := collector.NewTransformer(host, collector.ProcEnricher{})
	if err != nil {
		slog.Error("initialize transformer", "error", err)
		os.Exit(1)
	}
	metrics := &collector.Metrics{}
	if metricsAddress != "" {
		go serveMetrics(metricsAddress, source, metrics)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	runner := &collector.Runner{Source: source, Transformer: transformer, Sender: collector.NewHTTPSender(serverURL, 5*time.Second, 3), Metrics: metrics, BatchSize: batchSize, FlushInterval: flushInterval}
	slog.Info("collector started", "host_id", host.HostID, "boot_id", host.BootID, "server", serverURL, "object", objectPath)
	if err := runner.Run(ctx); err != nil && ctx.Err() == nil {
		slog.Error("collector stopped", "error", err)
		os.Exit(1)
	}
}

func serveMetrics(address string, source collector.SampleSource, metrics *collector.Metrics) {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(writer http.ResponseWriter, _ *http.Request) {
		kernel, err := source.Stats()
		if err != nil {
			http.Error(writer, err.Error(), http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("content-type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = writer.Write([]byte(metrics.Prometheus(kernel)))
	})
	server := &http.Server{Addr: address, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("collector metrics server stopped", "error", err)
	}
}

func parseUint32List(value string) ([]uint32, error) {
	values, err := parseUint64List(value)
	if err != nil {
		return nil, err
	}
	result := make([]uint32, 0, len(values))
	for _, item := range values {
		if item > uint64(^uint32(0)) {
			return nil, fmt.Errorf("value %d exceeds uint32", item)
		}
		result = append(result, uint32(item))
	}
	return result, nil
}

func parseUint64List(value string) ([]uint64, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	result := []uint64{}
	for _, raw := range strings.Split(value, ",") {
		parsed, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid unsigned integer %q: %w", raw, err)
		}
		result = append(result, parsed)
	}
	return result, nil
}
