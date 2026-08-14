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
  -detection-rules configs/detection-rules.yaml \
  -metrics 127.0.0.1:9091
```

可通过 `-exclude-pids`、`-exclude-uids`、`-exclude-cgroups` 设置内核过滤，
通过 `-watch-cgroups` 和 `-investigation-cgroups` 初始化动态采集等级。
`-exclude-path-prefixes /proc/,/var/log/` 会写入 LPM Trie，在内核侧对原始 syscall
路径前缀降噪；相对路径、dirfd、软链接可能改变最终对象，因此该参数不能作为安全白名单。

Collector 默认启用四级 UploadPolicy：高风险事件实时上报、上下文事件保留到 Alert
回捞、稳定网络和进程生命周期事件聚合上报、普通文件读取仅在本地保留聚合摘要。主要资源参数：

```bash
-aggregate-window 1m
-aggregate-max-keys 16384
-on-alert-buffer-ttl 2m
-on-alert-buffer-bytes 134217728
-on-alert-buffer-scope-bytes 4194304
-post-alert-window 2m
-high-flush-interval 100ms
```

`-detection-rules` 指向 CEL 黑白名单 Bundle；传空字符串可停用 CEL 并只使用内置兜底
规则。修改规则文件后向 Collector 发送 `SIGHUP` 即可原子热更新；若新 Bundle 无法解析
或编译，Collector 会保留最后一个有效规则版本并增加 reload error 指标。黑名单优先于
白名单，白名单不跳过 UploadPolicy。

所有缓存同时受 TTL 和字节上限约束；批量 JSON 超过阈值时使用 gzip，上报服务端可
直接解压处理。

完整设计、ABI 和 Ring Buffer 背压策略见
[`docs/EBPF_RING_BUFFER_DESIGN.md`](../docs/EBPF_RING_BUFFER_DESIGN.md)。
