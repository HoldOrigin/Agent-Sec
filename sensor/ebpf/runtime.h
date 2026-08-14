// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#ifndef __SENTINEL_RUNTIME_H
#define __SENTINEL_RUNTIME_H

#define RUNTIME_EVENT_ABI_VERSION 1
#define RUNTIME_COMM_LEN 16
#define RUNTIME_ARG0_LEN 256
#define RUNTIME_ARG1_LEN 128
#define RUNTIME_ADDR_LEN 16
#define RUNTIME_STATS_KEY 0

enum runtime_event_type {
    EVENT_PROCESS_FORK = 1,
    EVENT_PROCESS_EXEC = 2,
    EVENT_PROCESS_EXIT = 3,
    EVENT_FILE_OPEN = 10,
    EVENT_FILE_CREATE = 11,
    EVENT_FILE_CHMOD = 12,
    EVENT_FILE_UNLINK = 13,
    EVENT_NETWORK_CONNECT = 20,
};

enum collection_level {
    COLLECTION_NORMAL = 0,
    COLLECTION_WATCH = 1,
    COLLECTION_INVESTIGATION = 2,
};

enum runtime_event_flags {
    EVENT_FLAG_NONE = 0,
    EVENT_FLAG_IPV4 = 1 << 0,
    EVENT_FLAG_IPV6 = 1 << 1,
    EVENT_FLAG_TRUNCATED = 1 << 2,
};

/*
 * Stable kernel/userspace ABI. Keep fixed-width fields and append-only changes.
 * sizeof(struct runtime_event) is 496 bytes for ABI v1.
 */
struct runtime_event {
    __u16 abi_version;
    __u16 size;
    __u32 type;
    __u64 timestamp_ns;
    __u64 cgroup_id;
    __u64 process_start_ns;
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __s32 operation_flags;
    __u16 address_family;
    __u16 destination_port;
    __u8 protocol;
    __u8 collection_level;
    __u16 flags;
    __u8 destination_addr[RUNTIME_ADDR_LEN];
    char comm[RUNTIME_COMM_LEN];
    char parent_comm[RUNTIME_COMM_LEN];
    char arg0[RUNTIME_ARG0_LEN];
    char arg1[RUNTIME_ARG1_LEN];
};

struct runtime_stats {
    __u64 emitted;
    __u64 reserve_failed;
    __u64 filtered;
};

#endif
