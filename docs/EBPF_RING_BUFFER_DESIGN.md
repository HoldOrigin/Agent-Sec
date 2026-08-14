# eBPF Sensor 与 Ring Buffer 设计

## 1. 目标与边界

本设计补齐 MVP 从 Linux 内核事件到 Go 服务端的真实采集链路。内核程序只采集
可验证事实；行为判定、图谱关联、Incident 和 AI 调查继续位于用户态。

```text
Linux tracepoints
  -> CO-RE eBPF probes
  -> fixed ABI runtime_event
  -> 8 MiB BPF ring buffer
  -> Go collector decode/enrich/batch
  -> POST /api/events/batch
  -> Processor -> Behavior -> Graph -> Incident
```

实现文件：

- `sensor/ebpf/runtime.h`：内核/用户态共享 ABI 定义；
- `sensor/ebpf/runtime.bpf.c`：探针、过滤 Map、采集等级和 Ring Buffer；
- `internal/sensorabi`：Go ABI 解码与校验；
- `internal/collector`：Linux 加载器、Ring Buffer Reader、转换、批量发送和指标；
- `cmd/collector`：Linux Collector 进程入口。

## 2. 探针设计

| Tracepoint | 事件 | 关键字段 | 语义 |
|---|---|---|---|
| `sched/sched_process_fork` | `process_fork` | child PID、parent PID、comm | 创建进程/线程事实 |
| `syscalls/sys_enter_execve` | `process_exec` | filename、argv[1] | exec 尝试 |
| `sched/sched_process_exit` | `process_exit` | PID/TGID、comm | 进程/线程退出 |
| `syscalls/sys_enter_openat` | `file_open` / `file_create` | path、open flags | 文件打开/创建尝试 |
| `syscalls/sys_enter_fchmodat` | `file_chmod` | path、mode | 权限修改尝试 |
| `syscalls/sys_enter_unlinkat` | `file_unlink` | path | 删除尝试 |
| `syscalls/sys_enter_connect` | `network_connect` | family、IP、port | IPv4/IPv6 连接尝试 |

MVP 使用稳定 tracepoint，降低对内核函数签名的依赖；通过 CO-RE 读取
`task_struct` 的父进程和启动时间。`connect(2)` 不提供 socket type，因此协议字段默认
为 unknown，后续可使用 socket state enrichment 补充 TCP/UDP。`sys_enter_*` 不能证明
系统调用成功；生产版本可增加 enter/exit 关联 Map，仅在返回值成功时输出完成事件。

## 3. 稳定事件 ABI

ABI v1 固定为 496 字节，使用 little-endian 定长整数和定长字符数组，避免内核指针、
变长数据或 Go 结构体自然 padding。加载 Collector 时会校验 Go 布局；每条样本还会
校验 `abi_version`、`size` 和 `type`。

| 字段组 | 字段 | 说明 |
|---|---|---|
| Header | `abi_version`, `size`, `type` | 兼容性和事件分派 |
| Identity | `timestamp_ns`, `cgroup_id`, `process_start_ns` | 单调时钟、容器范围、PID 复用防护 |
| Process | `pid`, `tgid`, `ppid`, `uid`, `gid` | 线程和进程身份 |
| Operation | `operation_flags` | open flags 或 chmod mode |
| Network | family、port、protocol、16-byte address | IPv4/IPv6 统一存储 |
| Context | collection level、flags、comm、parent comm | 采集和关联上下文 |
| Arguments | `arg0[256]`, `arg1[128]` | 文件/可执行路径和一个关键参数 |

ABI 变更遵守追加原则：不重排或修改已有字段；不兼容变更必须提升版本。字符数组可能
被截断，用户态始终按首个 NUL 解码。当前 BPF helper 无法可靠区分所有截断情况，
`EVENT_FLAG_TRUNCATED` 保留给后续版本使用。

内核单调时间通过 `/proc/stat` 的 `btime` 转成 UTC；进程实体仍使用
`host_id + boot_id + tgid + process_start_ns`，避免 PID 重用导致错误关联。

## 4. Ring Buffer

### 4.1 选择

采用 `BPF_MAP_TYPE_RINGBUF`，容量 8 MiB。与 per-CPU perf buffer 相比，全局 Ring
Buffer 保留跨 CPU 的提交顺序，且只有一个共享容量池，适合进程、文件、网络事件的
时间链关联。496 字节固定 payload 未计内部头部时，8 MiB 理论可容纳约 16,900 条
待消费事件。

### 4.2 写入协议

每个探针执行以下过程：

1. 读取 PID/UID/cgroup 并命中过滤 Map 时立即返回；
2. 调用 `bpf_ringbuf_reserve()` 预留一条固定事件；
3. 预留失败则增加当前 CPU 的 `reserve_failed`，不阻塞内核线程；
4. 清零结构、填充公共和事件专属字段；
5. 合法事件用 `bpf_ringbuf_submit()` 提交，并增加 `emitted`；
6. socket 地址读取失败时用 `bpf_ringbuf_discard()` 放弃未完成样本。

内核热路径绝不等待用户态。Ring Buffer 满时明确丢弃新事件，由指标报警；这是为了
保护被监控业务，不把安全采集器变成系统延迟来源。

### 4.3 读取、背压与交付

Go Collector 使用 `github.com/cilium/ebpf/ringbuf.Reader` 阻塞读取。RawSample 会先复制
再解码，避免下一次读取复用底层内存。流水线为：

```text
ringbuf.Reader
  -> ABI validation
  -> /proc cgroup enrichment
  -> bounded userspace channel (4 x batch size)
  -> max 100 events or 500 ms
  -> HTTP batch, 5 s timeout, 3 exponential retries
```

用户态队列满时读取 goroutine 阻塞，压力向 Ring Buffer 传递，最终由
`reserve_failed` 表达数据损失。发送失败在重试耗尽后使 Collector 明确退出，交由
systemd/Kubernetes 重启；MVP 不伪装成成功，也不提供磁盘 WAL。生产部署若要求断网
不丢事件，应在批量发送前增加有容量上限、加密且可恢复的本地 spool。

### 4.4 指标与容量调整

Collector 的 `:9091/metrics` 输出：

- `sentinel_ebpf_events_emitted_total`；
- `sentinel_ebpf_ringbuf_reserve_failed_total`；
- `sentinel_ebpf_events_filtered_total`；
- samples、decode errors、transformed、submitted、send errors、batches。

内核计数使用 `BPF_MAP_TYPE_PERCPU_ARRAY`，写入无跨 CPU 竞争；Go 读取时汇总所有
CPU。建议对 `rate(reserve_failed[5m]) > 0` 报警，并同时检查服务端延迟、Collector
CPU、事件速率和批次大小。容量调优先减少低价值采集，再考虑扩大 Ring Buffer。

## 5. Map 与动态采集等级

| Map | 类型 | 最大项 | 用途 |
|---|---|---:|---|
| `events` | RINGBUF | 8 MiB | 内核到用户态事件通道 |
| `exclude_pid` | HASH | 4096 | 排除 agent 和指定进程 |
| `exclude_uid` | HASH | 4096 | 排除指定用户 |
| `exclude_cgroup` | HASH | 4096 | 排除指定容器/工作负载 |
| `exclude_path_prefix` | LPM_TRIE | 256 | 原始路径前缀性能降噪，不作为安全边界 |
| `collection_level` | LRU_HASH | 16384 | cgroup -> NORMAL/WATCH/INVESTIGATION |
| `stats` | PERCPU_ARRAY | 1 | emitted/reserve-failed/filtered |

NORMAL 始终采集 exec、exit、create、chmod、unlink、connect 等安全关键事实，并抑制
普通 `file_open`；WATCH/INVESTIGATION 额外开启 `file_open`。当前两个高等级的事件
集合相同，但等级随事件上报，服务端可采用不同的保留期和调查策略。后续可在
INVESTIGATION 增加 argv、DNS、rename、write 和 socket state，而不改变正常态成本。

Collector 提供 `SetCollectionLevel(cgroupID, level)`；CLI 可通过 `-watch-cgroups` 和
`-investigation-cgroups` 初始化。下一阶段应让 Collector 订阅服务端策略流并带 TTL
更新 Map，过期后删除 key 自动回到 NORMAL。

## 6. 容器元数据与事件转换

采样发生后立即读取 `/proc/<tgid>/cgroup`，提取 container ID 和 Kubernetes pod UID；
进程退出过快时可能无法补充元数据，此时仍保留数字 cgroup ID。namespace、pod 名和
workload 需要 Kubernetes CRI/API 缓存，MVP 不在内核态解析这些控制面信息。

转换后的对象与现有 `/api/events/batch` 输入兼容，网络、文件和 exec 专属字段放在
`metadata`，服务端继续负责去重、低价值过滤和行为图谱派生。

## 7. 安全、权限和部署

- 推荐 Linux 5.8+、启用 BTF 和 BPF Ring Buffer；
- 新内核授予 `CAP_BPF`、`CAP_PERFMON`，部分环境仍需 `CAP_SYS_ADMIN`；
- Collector 需要读取 `/proc`，容器部署时需挂载 host `/proc` 和目标内核 BTF；
- HTTP 生产链路应使用 mTLS、节点身份认证、请求大小限制和服务端幂等 event ID；
- 排除 Collector 自身 PID，避免自观测噪声；
- eBPF object 应在 CI 中对目标内核矩阵执行 verifier/load 测试并做制品签名。

## 8. 构建和运行

Linux 安装 clang/LLVM、bpftool、libbpf headers 后：

```bash
make sensor
make build
./bin/sentinel
sudo ./bin/sentinel-collector \
  -object sensor/ebpf/runtime.bpf.o \
  -server http://127.0.0.1:8080
```

开发机是 Windows 时仍可运行全部平台无关的 ABI、转换和发送测试，并交叉编译 Linux
Collector；内核 object 的 Clang 编译、verifier 和真实 Ring Buffer 压测必须在 Linux
CI/VM 完成。

## 9. MVP 已知限制与下一步

1. 使用 syscall enter，因此 file/connect 是“尝试”而非“成功”；增加 enter/exit 状态关联。
2. exec 仅捕获 filename 与 argv[1]；使用按等级受控的 argv chunk 事件扩展长命令行。
3. connect protocol 未在内核侧确认；增加 socket cookie/state enrichment。
4. `/proc` enrichment 存在短命进程竞态；增加 cgroup/container 缓存和 CRI watcher。
5. 无本地 WAL；增加有界 spool、确认水位和重放去重。
6. 策略 Map 只支持启动参数/API 方法；增加服务端策略订阅、TTL 和版本确认。
7. 当前 Windows 环境无法执行 verifier；在 Linux CI 覆盖 amd64/arm64 和内核矩阵。

## 10. 采集、检测与上报严格解耦

集群基线检查和容器运行时审计不能演变为全量日志平台。系统必须把三个问题拆成独立
策略，任何白名单都不能同时、隐式地控制三层：

```text
CollectionPolicy  决定内核 Hook、字段和采集等级
DetectionPolicy   决定节点本地是否形成安全判定
UploadPolicy      决定原始事件、上下文或聚合结果是否离开节点
```

一个事件可以“已采集、本地未告警、仅聚合上报”，也可以“已采集、暂不上报、Alert
后回捞”。白名单只抑制指定阶段，不删除审计事实；黑名单或本地高风险规则命中始终具有
最高上报优先级。

数据路径采用三层过滤：

```text
eBPF Kernel Filter
  -> Go User-space Filter / Aggregate / Rolling Buffer
  -> Upload Filter with high/normal priority batches
  -> Server behavior correlation
```

### 10.1 CollectionPolicy：内核先过滤

内核只做稳定、常数时间且 verifier 友好的粗过滤：

- Agent 自身 PID；
- 明确排除的 UID 和 cgroup ID；
- 通过 LPM Trie 配置的原始路径前缀降噪；
- cgroup 对应的 NORMAL/WATCH/INVESTIGATION 等级；
- 高价值状态变化事件；
- NORMAL 状态下关闭普通 `file_open` 等高频 Hook。

默认不全量 Hook `read`、`write`、`send`、`recv` 或逐包路径。优先采集 exec、create、
chmod、unlink、connect、namespace、mount、root、privilege 和 ptrace 等状态变化。

PID 会复用，UID 范围通常过大，所以它们只能用于性能降噪，不能单独作为强信任身份。
cgroup 规则必须随容器生命周期更新并带 TTL。syscall 参数中的路径可能是相对路径、
包含 `..`、依赖 dirfd 或随后经过符号链接；路径前缀 Map 可以降噪，但不能作为不可绕过
的安全白名单。敏感路径判定应逐步转向成功返回事件和 mount/inode/device 身份。

### 10.2 DetectionPolicy：本地安全判断

Collector 在完成进程和容器上下文补充后执行本地确定性规则。第一阶段使用 CEL
黑白名单规则，并保留 Go 内置谓词作为安全兜底。当前高风险判断包括：

- 黑名单或外部检测器写入 `metadata.blacklist_hit/security_alert`；
- 临时目录程序执行；
- Web 进程派生 Shell；
- 临时文件增加执行权限；
- `/etc`、`/root`、`/boot` 和系统二进制目录发生修改；
- namespace/mount/root/privilege/ptrace 等关键状态变化。

规则 Bundle 位于 `configs/detection-rules.yaml`。加载器采用严格 YAML 字段校验，限制最多
1,000 条规则和单条 4,096 字节；每条 CEL 求值限制为 10,000 cost units。规则按优先级
降序执行，并坚持 blacklist 优先于 whitelist（deny-overrides）。Collector 启动时完整编译
规则；收到 `SIGHUP` 后先编译不可变快照再原子切换，非法更新不会覆盖最后一个有效版本。
命中结果写入 `metadata.detection_rule_id/detection_severity/detection_reason`，黑名单还会写入
`security_alert=true` 和 `blacklist_hit=true`。白名单只抑制本地检测谓词，不绕过独立的
UploadPolicy 和审计保留策略。

### 10.3 UploadPolicy：服务端按需接收

| 模式 | 行为 | 默认事件 |
|---|---|---|
| `ALWAYS` | 高优先级、100ms 内进入上报批次 | 本地规则命中、关键状态变化、调查态事件 |
| `ON_ALERT` | 节点有界滚动缓存，Alert 时回捞 | exec、file create/write/chmod/unlink、外部 connect |
| `AGGREGATE` | 按实体和目标折叠，周期上报 Meta-Event | 稳定内部 connect、accept、DNS、fork/exit |
| `LOCAL_ONLY` | 先在本地聚合，短期缓存摘要且不默认上传 | 多数 file open/read 和低价值探测 |

每条上报或缓存事件在 `metadata` 中记录 `upload_mode`、`upload_priority` 和
`upload_reason`。ALWAYS 决策使用高优先级批次，AGGREGATE 使用普通优先级批次；两者
互不阻塞。

## 11. 用户态聚合

Collector 对高频重复事件按以下 key 聚合：

```text
cgroup/container scope
event type
process executable
destination IP/port/protocol 或 DNS query/path
```

聚合窗口默认 60 秒，最大同时维护 16,384 个 key。达到上限时优先输出最久未更新的
bucket，而不是无限增加内存。Meta-Event 保留原 event type，并在 metadata 中加入：

```json
{
  "aggregate": true,
  "aggregate_count": 500,
  "aggregate_window": "1m0s",
  "aggregate_first_seen": "...",
  "aggregate_last_seen": "..."
}
```

网络路径只采集连接生命周期事件，默认不采集每次 send/recv。新公网目标、黑名单目标、
临时目录程序外联、异常端口或 DNS 高熵/NXDOMAIN 爆发应由 DetectionPolicy 升级为
ALWAYS，不能只留下统计摘要。

## 12. ON_ALERT 滚动缓存与证据回捞

滚动缓存同时受时间和字节约束，不能只配置“保留五分钟”：

- 默认 TTL：2 分钟；
- 全节点最大估算 JSON 大小：128 MiB；
- 单 cgroup/container：4 MiB；
- 超限时先淘汰全局或该 scope 最旧事件；
- 单条事件超过 scope/global 上限时直接拒绝缓存并计数；
- LOCAL_ONLY 原始事件先按 key 聚合，本地只缓存摘要，且不会被普通 Alert 自动提升；
- ON_ALERT 事件按 cgroup/container 回捞并标记 `promoted_context=true`。

本地 Alert 形成后，该 scope 默认进入两分钟 post-alert 窗口。在此期间新的 ON_ALERT
事件直接走高优先级上报，从而得到“Alert 前上下文 + 触发事件 + Alert 后行为”。生产版
可将紧凑二进制缓存替代当前基于 Go Map 的第一阶段实现，并增加加密磁盘 spool。

## 13. 背压与降级

当前资源边界为固定 8 MiB Ring Buffer、有界输入 channel、有界滚动缓存、有界聚合
key 和批次大小。后续自适应控制遵循：

1. 用户态队列超过 70% 时停止低价值事件进入普通上报队列；
2. 超过 85% 或 `reserve_failed` 增长时只保留 ALWAYS 和已提升证据；
3. 发送延迟持续升高时扩大聚合窗口；
4. 恢复使用迟滞窗口逐级完成，避免 NORMAL/WATCH 反复震荡；
5. 高优先级事件不能被普通聚合批次饿死。

Collector 暴露以下阶段指标：upload mode 计数、aggregate input/output、context promoted、
buffer bytes/entries/evictions、active alert scopes、input queue depth，以及现有 Ring Buffer
reserve-failed。由这些指标验证事件守恒关系和定位丢失发生在哪一层。

## 14. 当前实现范围

本阶段已经实现 UploadPolicy 四级分类、CEL 黑白名单及内置高风险兜底谓词、规则原子
热更新、两分钟 post-alert scope、有界滚动缓存、用户态聚合、高/普通优先级批次、gzip
传输和 Prometheus 指标。服务端把本地策略命中转换为 `B900 LocalSecurityPolicyMatch`，
无需等待攻击链关联即可生成 Alert。尚未实现的部分：

- 中心规则 Bundle 分发、签名校验和版本确认；
- Collector 到服务端的 mTLS、节点身份认证和检测字段来源校验；
- namespace/mount/privilege/ptrace 新 eBPF Hook；
- DNS 采集 Hook 和异常域名检测；
- syscall enter/exit 成功语义；
- 自适应内核 Map 降级控制；
- 加密磁盘 spool 和服务端 ACK 水位。
