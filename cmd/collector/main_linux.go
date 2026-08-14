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
	var highFlushInterval time.Duration
	var aggregateWindow time.Duration
	var bufferTTL time.Duration
	var postAlertWindow time.Duration
	var bufferMaxBytes int64
	var bufferMaxBytesPerScope int64
	var maxAggregateKeys int
	var detectionRules string
	var excludePIDs string
	var excludeUIDs string
	var excludeCgroups string
	var excludePathPrefixes string
	var watchCgroups string
	var investigationCgroups string
	flag.StringVar(&objectPath, "object", "sensor/ebpf/runtime.bpf.o", "compiled CO-RE eBPF object")
	flag.StringVar(&serverURL, "server", "http://127.0.0.1:8080", "Sentinel server base URL")
	flag.StringVar(&metricsAddress, "metrics", "127.0.0.1:9091", "collector metrics listen address; empty disables it")
	flag.IntVar(&batchSize, "batch-size", 100, "maximum events per API batch")
	flag.DurationVar(&flushInterval, "flush-interval", 500*time.Millisecond, "maximum event batch delay")
	flag.DurationVar(&highFlushInterval, "high-flush-interval", 100*time.Millisecond, "maximum delay for ALWAYS and promoted events")
	flag.DurationVar(&aggregateWindow, "aggregate-window", time.Minute, "window used to fold high-frequency events")
	flag.DurationVar(&bufferTTL, "on-alert-buffer-ttl", 2*time.Minute, "retention for local ON_ALERT and LOCAL_ONLY events")
	flag.DurationVar(&postAlertWindow, "post-alert-window", 2*time.Minute, "period that ON_ALERT events are uploaded after a local alert")
	flag.Int64Var(&bufferMaxBytes, "on-alert-buffer-bytes", 128*1024*1024, "global byte limit for the local rolling event buffer")
	flag.Int64Var(&bufferMaxBytesPerScope, "on-alert-buffer-scope-bytes", 4*1024*1024, "per-cgroup byte limit for the local rolling event buffer")
	flag.IntVar(&maxAggregateKeys, "aggregate-max-keys", 16384, "maximum concurrent user-space aggregation keys")
	flag.StringVar(&detectionRules, "detection-rules", "configs/detection-rules.yaml", "CEL blacklist/whitelist YAML bundle; empty disables it")
	flag.StringVar(&excludePIDs, "exclude-pids", "", "comma-separated process IDs to filter")
	flag.StringVar(&excludeUIDs, "exclude-uids", "", "comma-separated user IDs to filter")
	flag.StringVar(&excludeCgroups, "exclude-cgroups", "", "comma-separated numeric cgroup IDs to filter")
	flag.StringVar(&excludePathPrefixes, "exclude-path-prefixes", "", "comma-separated absolute raw path prefixes for performance filtering")
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
	pathPrefixes, err := parsePathPrefixes(excludePathPrefixes)
	if err != nil {
		slog.Error("parse excluded path prefixes", "error", err)
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
	source, err := collector.OpenLinuxSource(collector.SourceConfig{ObjectPath: objectPath, ExcludePIDs: pids, ExcludeUIDs: uids, ExcludeCgroups: cgroups, ExcludePathPrefixes: pathPrefixes, CollectionLevels: levels})
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
	var detectionPolicy collector.DetectionPolicy = collector.NewDefaultDetectionPolicy()
	var reloadablePolicy *collector.CELDetectionPolicy
	if detectionRules != "" {
		reloadablePolicy, err = collector.LoadCELDetectionPolicy(detectionRules, detectionPolicy, metrics)
		if err != nil {
			slog.Error("load CEL detection rules", "error", err, "path", detectionRules)
			os.Exit(1)
		}
		detectionPolicy = reloadablePolicy
	}
	router := collector.NewUploadRouter(collector.UploadRouterConfig{
		BufferTTL:              bufferTTL,
		BufferMaxBytes:         bufferMaxBytes,
		BufferMaxBytesPerScope: bufferMaxBytesPerScope,
		AggregateWindow:        aggregateWindow,
		MaxAggregateKeys:       maxAggregateKeys,
		PostAlertWindow:        postAlertWindow,
	}, detectionPolicy, collector.NewDefaultUploadPolicy(), metrics)
	if metricsAddress != "" {
		go serveMetrics(metricsAddress, source, metrics)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if reloadablePolicy != nil {
		reloadSignals := make(chan os.Signal, 1)
		signal.Notify(reloadSignals, syscall.SIGHUP)
		defer signal.Stop(reloadSignals)
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-reloadSignals:
					if err := reloadablePolicy.ReloadFile(detectionRules); err != nil {
						slog.Error("reload CEL detection rules", "error", err, "path", detectionRules)
						continue
					}
					slog.Info("reloaded CEL detection rules", "version", reloadablePolicy.Version())
				}
			}
		}()
	}
	runner := &collector.Runner{Source: source, Transformer: transformer, Sender: collector.NewHTTPSender(serverURL, 5*time.Second, 3, metrics), Router: router, Metrics: metrics, BatchSize: batchSize, FlushInterval: flushInterval, HighFlushInterval: highFlushInterval}
	detectionVersion := "builtin"
	if reloadablePolicy != nil {
		detectionVersion = reloadablePolicy.Version()
	}
	slog.Info("collector started", "host_id", host.HostID, "boot_id", host.BootID, "server", serverURL, "object", objectPath, "detection_rules_version", detectionVersion)
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

func parsePathPrefixes(value string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	result := []string{}
	for _, raw := range strings.Split(value, ",") {
		prefix := strings.TrimSpace(raw)
		if !strings.HasPrefix(prefix, "/") {
			return nil, fmt.Errorf("path prefix %q must be absolute", prefix)
		}
		if len(prefix) >= 256 {
			return nil, fmt.Errorf("path prefix %q exceeds the 255-byte limit", prefix)
		}
		result = append(result, prefix)
	}
	return result, nil
}
