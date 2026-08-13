# Linux eBPF Runtime Sensor

`ebpf/runtime.bpf.c` 是 MVP 的 CO-RE 事实采集骨架，覆盖：

- Process exec/exit
- File open/chmod
- Outbound connect syscall
- PID、PPID、UID、cgroup ID 和时间戳
- `exclude_pid`、`exclude_cgroup` 内核过滤 Map

Sensor 不包含任何 `malicious=true` 判断。用户态 Collector 需要解析文件和 Socket 参数、补充容器元数据，并转换为服务端 `/api/events` 接受的 RuntimeEvent。

编译需要 Linux、Clang、libbpf 和由目标内核 BTF 生成的 `vmlinux.h`：

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I./ebpf -c ebpf/runtime.bpf.c -o runtime.bpf.o
```

当前 Windows 开发环境无法加载或验证内核程序，因此项目默认使用 `datasets/web_rce.jsonl` 做确定性回放。生产化前仍需补充用户态 ring buffer Collector、Socket 地址解析、容器缓存、丢包指标和多内核版本兼容测试。
