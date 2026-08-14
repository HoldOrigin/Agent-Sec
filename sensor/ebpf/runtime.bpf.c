// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// CO-RE runtime sensor. It emits facts only; detection stays in userspace.
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "runtime.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile __u64 agent_cgroup_id = 0;
const volatile __u32 agent_pid = 0;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 8 * 1024 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} exclude_pid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u8);
} exclude_uid SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, __u8);
} exclude_cgroup SEC(".maps");

/* Performance-only raw pathname prefix exclusions. Not a security boundary. */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 256);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct runtime_path_lpm_key);
    __type(value, __u8);
} exclude_path_prefix SEC(".maps");

/* cgroup_id -> NORMAL/WATCH/INVESTIGATION */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, __u8);
} collection_level SEC(".maps");

/* Per-CPU counters avoid cross-CPU contention in the hot path. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct runtime_stats);
} stats SEC(".maps");

static __always_inline struct runtime_stats *get_stats(void)
{
    __u32 key = RUNTIME_STATS_KEY;
    return bpf_map_lookup_elem(&stats, &key);
}

static __always_inline void count_filtered(void)
{
    struct runtime_stats *value = get_stats();
    if (value)
        value->filtered++;
}

static __always_inline int should_drop(__u32 tgid, __u32 uid, __u64 cgroup_id)
{
    if ((agent_pid && tgid == agent_pid) ||
        (agent_cgroup_id && cgroup_id == agent_cgroup_id) ||
        bpf_map_lookup_elem(&exclude_pid, &tgid) ||
        bpf_map_lookup_elem(&exclude_uid, &uid) ||
        bpf_map_lookup_elem(&exclude_cgroup, &cgroup_id)) {
        count_filtered();
        return true;
    }
    return false;
}

static __always_inline int read_path_key(struct runtime_path_lpm_key *key, const void *path)
{
    int length = bpf_probe_read_user_str(key->data, sizeof(key->data), path);
    if (length <= 1)
        return length;
    key->prefixlen = (length - 1) * 8;
    return length;
}

static __always_inline int should_drop_path(struct runtime_path_lpm_key *key)
{
    if (key->prefixlen && bpf_map_lookup_elem(&exclude_path_prefix, key)) {
        count_filtered();
        return 1;
    }
    return 0;
}

static __always_inline struct runtime_event *reserve_event(__u32 type)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 pid = (__u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;
    __u32 uid = (__u32)uid_gid;
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    struct runtime_stats *counter;
    struct runtime_event *event;
    struct task_struct *task;
    struct task_struct *parent;
    __u8 *level;

    if (should_drop(tgid, uid, cgroup_id))
        return 0;

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (!event) {
        counter = get_stats();
        if (counter)
            counter->reserve_failed++;
        return 0;
    }

    __builtin_memset(event, 0, sizeof(*event));
    event->abi_version = RUNTIME_EVENT_ABI_VERSION;
    event->size = sizeof(*event);
    event->type = type;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->cgroup_id = cgroup_id;
    event->pid = pid;
    event->tgid = tgid;
    event->uid = uid;
    event->gid = uid_gid >> 32;
    /* connect(2) doesn't expose the socket type; userspace may enrich it. */
    event->protocol = 0;

    task = (struct task_struct *)bpf_get_current_task();
    parent = BPF_CORE_READ(task, real_parent);
    event->ppid = BPF_CORE_READ(parent, tgid);
    if (bpf_core_field_exists(task->start_boottime))
        event->process_start_ns = BPF_CORE_READ(task, start_boottime);
    else
        event->process_start_ns = BPF_CORE_READ(task, start_time);
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    BPF_CORE_READ_STR_INTO(&event->parent_comm, parent, comm);

    level = bpf_map_lookup_elem(&collection_level, &cgroup_id);
    event->collection_level = level ? *level : COLLECTION_NORMAL;
    return event;
}

static __always_inline void submit_event(struct runtime_event *event)
{
    struct runtime_stats *counter;
    if (!event)
        return;
    counter = get_stats();
    if (counter)
        counter->emitted++;
    bpf_ringbuf_submit(event, 0);
}

SEC("tracepoint/sched/sched_process_fork")
int on_process_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    struct runtime_event *event = reserve_event(EVENT_PROCESS_FORK);
    if (!event)
        return 0;
    __builtin_memcpy(event->parent_comm, event->comm, sizeof(event->parent_comm));
    event->pid = ctx->child_pid;
    event->tgid = ctx->child_pid;
    event->ppid = ctx->parent_pid;
    event->process_start_ns = event->timestamp_ns;
    bpf_probe_read_kernel_str(event->comm, sizeof(event->comm), ctx->child_comm);
    bpf_probe_read_kernel_str(event->arg0, sizeof(event->arg0), ctx->child_comm);
    submit_event(event);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int on_execve(struct trace_event_raw_sys_enter *ctx)
{
    const char *const *argv = (const char *const *)ctx->args[1];
    const char *argv1 = 0;
    struct runtime_event *event = reserve_event(EVENT_PROCESS_EXEC);
    if (!event)
        return 0;
    bpf_probe_read_user_str(event->arg0, sizeof(event->arg0), (const void *)ctx->args[0]);
    if (argv && !bpf_probe_read_user(&argv1, sizeof(argv1), &argv[1]) && argv1)
        bpf_probe_read_user_str(event->arg1, sizeof(event->arg1), argv1);
    submit_event(event);
    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int on_process_exit(void *ctx)
{
    submit_event(reserve_event(EVENT_PROCESS_EXIT));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int on_openat(struct trace_event_raw_sys_enter *ctx)
{
    __u32 flags = (__u32)ctx->args[2];
    __u32 type = (flags & 0100) ? EVENT_FILE_CREATE : EVENT_FILE_OPEN; /* O_CREAT */
    __u64 cgroup_id = bpf_get_current_cgroup_id();
    __u8 *level;
    struct runtime_path_lpm_key path_key = {};
    int path_length;
    if (type == EVENT_FILE_OPEN) {
        level = bpf_map_lookup_elem(&collection_level, &cgroup_id);
        if (!level || *level == COLLECTION_NORMAL) {
            count_filtered();
            return 0;
        }
    }
    path_length = read_path_key(&path_key, (const void *)ctx->args[1]);
    if (path_length > 0 && should_drop_path(&path_key))
        return 0;
    struct runtime_event *event = reserve_event(type);
    if (!event)
        return 0;
    if (path_length > 0)
        __builtin_memcpy(event->arg0, path_key.data, sizeof(event->arg0));
    else
        bpf_probe_read_user_str(event->arg0, sizeof(event->arg0), (const void *)ctx->args[1]);
    event->operation_flags = flags;
    submit_event(event);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int on_fchmodat(struct trace_event_raw_sys_enter *ctx)
{
    struct runtime_path_lpm_key path_key = {};
    int path_length = read_path_key(&path_key, (const void *)ctx->args[1]);
    if (path_length > 0 && should_drop_path(&path_key)) 
        return 0;
    struct runtime_event *event = reserve_event(EVENT_FILE_CHMOD);
    if (!event)
        return 0;
    if (path_length > 0)
        __builtin_memcpy(event->arg0, path_key.data, sizeof(event->arg0));
    else
        bpf_probe_read_user_str(event->arg0, sizeof(event->arg0), (const void *)ctx->args[1]);
    event->operation_flags = (__s32)ctx->args[2]; /* mode */
    submit_event(event);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int on_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    struct runtime_path_lpm_key path_key = {};
    int path_length = read_path_key(&path_key, (const void *)ctx->args[1]);
    if (path_length > 0 && should_drop_path(&path_key))
        return 0;
    struct runtime_event *event = reserve_event(EVENT_FILE_UNLINK);
    if (!event)
        return 0;
    if (path_length > 0)
        __builtin_memcpy(event->arg0, path_key.data, sizeof(event->arg0));
    else
        bpf_probe_read_user_str(event->arg0, sizeof(event->arg0), (const void *)ctx->args[1]);
    submit_event(event);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int on_connect(struct trace_event_raw_sys_enter *ctx)
{
    const struct sockaddr *address = (const struct sockaddr *)ctx->args[1];
    struct runtime_event *event = reserve_event(EVENT_NETWORK_CONNECT);
    __u16 family = 0;
    if (!event)
        return 0;
    if (bpf_probe_read_user(&family, sizeof(family), &address->sa_family)) {
        bpf_ringbuf_discard(event, 0);
        return 0;
    }
    event->address_family = family;
    if (family == AF_INET) {
        struct sockaddr_in addr4 = {};
        if (bpf_probe_read_user(&addr4, sizeof(addr4), address))
            goto discard;
        event->destination_port = bpf_ntohs(addr4.sin_port);
        __builtin_memcpy(event->destination_addr, &addr4.sin_addr.s_addr, 4);
        event->flags |= EVENT_FLAG_IPV4;
    } else if (family == AF_INET6) {
        struct sockaddr_in6 addr6 = {};
        if (bpf_probe_read_user(&addr6, sizeof(addr6), address))
            goto discard;
        event->destination_port = bpf_ntohs(addr6.sin6_port);
        __builtin_memcpy(event->destination_addr, &addr6.sin6_addr, 16);
        event->flags |= EVENT_FLAG_IPV6;
    } else {
        goto discard;
    }
    submit_event(event);
    return 0;

discard:
    count_filtered();
    bpf_ringbuf_discard(event, 0);
    return 0;
}
