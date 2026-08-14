# Linux eBPF Runtime Sensor

`ebpf/runtime.bpf.c` 是 Sentinel 的 Linux CO-RE 事实采集器，配套的
`cmd/collector` 使用 Go 读取 Ring Buffer，并批量发送到服务端。

当前采集：

- 进程 fork、exec、exit；
- 文件 open/create、chmod、unlink；
- IPv4/IPv6 outbound connect；
- PID/TGID/PPID、UID/GID、cgroup ID、进程启动时间；
- NORMAL、WATCH、INVESTIGATION 动态采集等级；
- PID、UID、cgroup 内核过滤；
- emitted、filtered、ring-buffer reserve-failed 每 CPU 计数器。

Sensor 只发出事实，不在内核中判断 `malicious=true`。`sys_enter_*` 事件表示
操作尝试，服务端负责行为派生、图谱构建和关联检测。

## Linux 构建

要求：Linux 内核 BTF (`/sys/kernel/btf/vmlinux`)、Clang/LLVM、bpftool、
libbpf headers，以及 Go 1.26+。

```bash
make sensor
make build
```

ARM64 构建示例：

```bash
make -C sensor/ebpf TARGET_ARCH=arm64 MULTIARCH=aarch64-linux-gnu
```

## 运行

先启动 Sentinel Server，再以具备 eBPF 权限的用户运行 Collector：

```bash
./bin/sentinel
sudo ./bin/sentinel-collector \
  -object sensor/ebpf/runtime.bpf.o \
  -server http://127.0.0.1:8080 \
  -metrics 127.0.0.1:9091
```

可通过 `-exclude-pids`、`-exclude-uids`、`-exclude-cgroups` 设置内核过滤，
通过 `-watch-cgroups` 和 `-investigation-cgroups` 初始化动态采集等级。

完整设计、ABI 和 Ring Buffer 背压策略见
[`docs/EBPF_RING_BUFFER_DESIGN.md`](../docs/EBPF_RING_BUFFER_DESIGN.md)。
