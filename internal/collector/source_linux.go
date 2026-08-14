//go:build linux

package collector

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"sentinel/internal/sensorabi"
)

type SourceConfig struct {
	ObjectPath       string
	ExcludePIDs      []uint32
	ExcludeUIDs      []uint32
	ExcludeCgroups   []uint64
	CollectionLevels map[uint64]uint8
}

type LinuxSource struct {
	collection *ebpf.Collection
	reader     *ringbuf.Reader
	links      []link.Link
	closeOnce  sync.Once
	closeErr   error
}

func OpenLinuxSource(config SourceConfig) (*LinuxSource, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock limit: %w", err)
	}
	spec, err := ebpf.LoadCollectionSpec(config.ObjectPath)
	if err != nil {
		return nil, fmt.Errorf("load eBPF collection spec: %w", err)
	}
	agentPID := spec.Variables["agent_pid"]
	if agentPID == nil {
		return nil, errors.New("eBPF constant agent_pid is missing")
	}
	if err := agentPID.Set(uint32(currentPID())); err != nil {
		return nil, fmt.Errorf("set eBPF constants: %w", err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load eBPF collection: %w", err)
	}
	source := &LinuxSource{collection: collection}
	cleanup := true
	defer func() {
		if cleanup {
			_ = source.Close()
		}
	}()
	if err := source.populateExclusions(config); err != nil {
		return nil, err
	}
	for cgroupID, level := range config.CollectionLevels {
		if err := source.SetCollectionLevel(cgroupID, level); err != nil {
			return nil, err
		}
	}
	attachments := []struct {
		group   string
		name    string
		program string
	}{
		{"sched", "sched_process_fork", "on_process_fork"},
		{"sched", "sched_process_exit", "on_process_exit"},
		{"syscalls", "sys_enter_execve", "on_execve"},
		{"syscalls", "sys_enter_openat", "on_openat"},
		{"syscalls", "sys_enter_fchmodat", "on_fchmodat"},
		{"syscalls", "sys_enter_unlinkat", "on_unlinkat"},
		{"syscalls", "sys_enter_connect", "on_connect"},
	}
	for _, attachment := range attachments {
		program := collection.Programs[attachment.program]
		if program == nil {
			return nil, fmt.Errorf("eBPF program %q is missing", attachment.program)
		}
		attached, attachErr := link.Tracepoint(attachment.group, attachment.name, program, nil)
		if attachErr != nil {
			return nil, fmt.Errorf("attach tracepoint %s/%s: %w", attachment.group, attachment.name, attachErr)
		}
		source.links = append(source.links, attached)
	}
	eventsMap := collection.Maps["events"]
	if eventsMap == nil {
		return nil, errors.New("eBPF map events is missing")
	}
	source.reader, err = ringbuf.NewReader(eventsMap)
	if err != nil {
		return nil, fmt.Errorf("open ring buffer reader: %w", err)
	}
	cleanup = false
	return source, nil
}

func (source *LinuxSource) Read() ([]byte, error) {
	record, err := source.reader.Read()
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), record.RawSample...), nil
}

func (source *LinuxSource) Stats() (sensorabi.RuntimeStats, error) {
	statsMap := source.collection.Maps["stats"]
	if statsMap == nil {
		return sensorabi.RuntimeStats{}, errors.New("eBPF map stats is missing")
	}
	key := uint32(0)
	var perCPU []sensorabi.RuntimeStats
	if err := statsMap.Lookup(&key, &perCPU); err != nil {
		return sensorabi.RuntimeStats{}, fmt.Errorf("read per-CPU eBPF stats: %w", err)
	}
	var total sensorabi.RuntimeStats
	for _, value := range perCPU {
		total.Emitted += value.Emitted
		total.ReserveFailed += value.ReserveFailed
		total.Filtered += value.Filtered
	}
	return total, nil
}

func (source *LinuxSource) SetCollectionLevel(cgroupID uint64, level uint8) error {
	if level > 2 {
		return fmt.Errorf("collection level %d is invalid", level)
	}
	levels := source.collection.Maps["collection_level"]
	if levels == nil {
		return errors.New("eBPF map collection_level is missing")
	}
	if level == 0 {
		if err := levels.Delete(&cgroupID); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete collection level: %w", err)
		}
		return nil
	}
	if err := levels.Update(&cgroupID, &level, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update collection level: %w", err)
	}
	return nil
}

func (source *LinuxSource) Close() error {
	source.closeOnce.Do(func() {
		var closeErrors []error
		if source.reader != nil {
			closeErrors = append(closeErrors, source.reader.Close())
		}
		for index := len(source.links) - 1; index >= 0; index-- {
			closeErrors = append(closeErrors, source.links[index].Close())
		}
		if source.collection != nil {
			source.collection.Close()
		}
		source.closeErr = errors.Join(closeErrors...)
	})
	return source.closeErr
}

func (source *LinuxSource) populateExclusions(config SourceConfig) error {
	one := uint8(1)
	for _, item := range []struct {
		mapName string
		keys    []uint32
	}{{"exclude_pid", config.ExcludePIDs}, {"exclude_uid", config.ExcludeUIDs}} {
		mapped := source.collection.Maps[item.mapName]
		if mapped == nil {
			return fmt.Errorf("eBPF map %s is missing", item.mapName)
		}
		for _, key := range item.keys {
			if err := mapped.Update(&key, &one, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("populate %s: %w", item.mapName, err)
			}
		}
	}
	cgroups := source.collection.Maps["exclude_cgroup"]
	if cgroups == nil {
		return errors.New("eBPF map exclude_cgroup is missing")
	}
	for _, key := range config.ExcludeCgroups {
		if err := cgroups.Update(&key, &one, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("populate exclude_cgroup: %w", err)
		}
	}
	return nil
}
