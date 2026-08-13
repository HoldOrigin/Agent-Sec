// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// CO-RE MVP sensor: emits facts only. Detection stays in the server Behavior Engine.
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

enum runtime_event_type {
    EVENT_PROCESS_EXEC = 1,
    EVENT_PROCESS_EXIT = 2,
    EVENT_FILE_OPEN = 10,
    EVENT_FILE_CHMOD = 11,
    EVENT_NETWORK_CONNECT = 20,
};

struct runtime_event {
    __u64 timestamp_ns;
    __u64 cgroup_id;
    __u32 type;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __s32 syscall_ret;
    char comm[16];
    char arg0[256];
};

struct filter_key {
    __u64 value;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} exclude_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} exclude_cgroup SEC(".maps");

static __always_inline bool should_drop(__u32 pid, __u64 cgroup_id)
{
    return bpf_map_lookup_elem(&exclude_pid, &pid) ||
           bpf_map_lookup_elem(&exclude_cgroup, &cgroup_id);
}

static __always_inline struct runtime_event *reserve_event(__u32 type)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    if (should_drop(pid, cgroup_id))
        return 0;

    struct runtime_event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event)
        return 0;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->cgroup_id = cgroup_id;
    event->type = type;
    event->pid = pid;
    event->uid = (__u32)bpf_get_current_uid_gid();
    event->ppid = BPF_CORE_READ((struct task_struct *)bpf_get_current_task(), real_parent, tgid);
    event->syscall_ret = 0;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    return event;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int on_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct runtime_event *event = reserve_event(EVENT_PROCESS_EXEC);
    if (!event)
        return 0;
    bpf_probe_read_user_str(event->arg0, sizeof(event->arg0), (const void *)ctx->args[0]);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int on_process_exit(void *ctx)
{
    struct runtime_event *event = reserve_event(EVENT_PROCESS_EXIT);
    if (event)
        bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int on_openat(struct trace_event_raw_sys_enter *ctx)
{
    struct runtime_event *event = reserve_event(EVENT_FILE_OPEN);
    if (!event)
        return 0;
    bpf_probe_read_user_str(event->arg0, sizeof(event->arg0), (const void *)ctx->args[1]);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int on_fchmodat(struct trace_event_raw_sys_enter *ctx)
{
    struct runtime_event *event = reserve_event(EVENT_FILE_CHMOD);
    if (!event)
        return 0;
    bpf_probe_read_user_str(event->arg0, sizeof(event->arg0), (const void *)ctx->args[1]);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int on_connect(struct trace_event_raw_sys_enter *ctx)
{
    struct runtime_event *event = reserve_event(EVENT_NETWORK_CONNECT);
    if (event)
        bpf_ringbuf_submit(event, 0);
    return 0;
}
