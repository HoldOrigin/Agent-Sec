# eBPF 高危安全事件与 CEL 规则设计

## 1. 结论

高危运行时检测不能只判断“发生了某个 syscall”。可靠规则至少需要组合：事件结果、进程树、容器/命名空间、文件规范化路径、身份与能力变化、网络目标以及环境白名单。

本设计参考以下开源项目：

- [Falco 官方规则库](https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml)：容器终端 Shell、异常访问 Kubernetes API、Netcat RCE、凭据搜索等成熟检测规则。
- [Tetragon Observability Policy Library](https://tetragon.io/docs/policy-library/observability/)：临时目录执行、SUID/SGID 执行、文件能力提权、setuid/setgid、memfd 与已删除文件执行。
- [Tetragon File Monitoring 示例](https://github.com/cilium/tetragon/blob/main/examples/quickstart/file_monitoring.yaml)：敏感目录读写与 LSM/VFS 采集方式。
- [Tracee 内置安全事件目录](https://github.com/aquasecurity/tracee/blob/main/mkdocs.yml)：文件无落地执行、内核模块、ptrace/进程内存注入、cgroup release_agent、core_pattern、Kubernetes API、动态链接器预加载等事件。

## 2. 建议的风险分层

| 等级 | 行为类别 | 典型事件 | 默认处置 |
| --- | --- | --- | --- |
| P0 / critical | 容器逃逸与内核篡改 | `setns`/`unshare` 进入宿主命名空间、危险 mount、`pivot_root`/`chroot`、加载内核模块、加载异常 BPF 程序、修改 cgroup `release_agent`/`core_pattern` | 本地立即告警并 ALWAYS 上报 |
| P0 / critical | 提权与进程注入 | 非 root 到 root 的 `setuid`/`setgid`、危险 `capset`、SUID/文件能力执行、跨进程 `ptrace`、`process_vm_writev`、写 `/proc/<pid>/mem` | 本地立即告警并 ALWAYS 上报 |
| P1 / high | 文件无落地与恶意执行 | `/tmp`、`/dev/shm`、`memfd`、已删除 inode 执行；Web 服务派生 Shell；Netcat RCE | 本地告警并回捞上下文 |
| P1 / high | 持久化与敏感写入 | `ld.so.preload`、Cron、systemd unit、SSH authorized_keys、系统二进制目录写入 | 本地告警；包管理/运维进程必须写入规则内排除条件 |
| P1 / high | 控制面与运行时套接字 | 未授权容器访问 Kubernetes API、Docker/containerd/CRI socket | 本地告警并关联 ServiceAccount、Pod、源进程 |
| P2 / medium | 凭据访问与侦察 | 打开 `/etc/shadow`、`/root/.ssh`、搜索私钥、`sudo`、内核/网络枚举 | 默认 ON_ALERT 或仅调查模式采集，避免高噪声 |
| P2 / medium | 清除痕迹 | 删除 Shell history、认证日志、审计日志 | 与进程身份、logrotate/日志代理白名单组合后告警 |

## 3. 当前 Agent-Sec 能直接检测的规则

当前 Sensor 已采集 `process_exec`、`file_open`、`file_create`、`file_chmod`、`file_unlink` 和 IPv4/IPv6 `network_connect`。候选规则位于 `configs/detection-rules-researched.yaml`，包括：

1. 临时目录执行。
2. Web 服务派生 Shell。
3. 容器内 Netcat 使用 RCE 参数。
4. 创建 `/etc/ld.so.preload`。
5. 在 Cron/systemd 持久化目录创建文件。
6. 创建 root `authorized_keys`。
7. 临时目录文件增加可执行位。
8. 临时目录进程发起网络连接。
9. 删除 root Shell 历史。
10. 容器进程打开敏感凭据文件。

这些规则单事件即可判断，适合 CEL。多事件序列（例如“文件落地 -> chmod -> exec -> 外联”）应继续由 Go 行为关联引擎处理，不能用当前单事件 CEL 表达。

## 4. 尚需新增 Hook/字段的高价值规则

以下 CEL 是目标事件模型，不应在当前规则包中启用。

### 4.1 进入宿主命名空间

需要采集 `setns`、`unshare` 或 `switch_task_ns`，并比较调用前后的 namespace inode：

```cel
event.event_type == "namespace_change" &&
event.container.container_id != "" &&
event.metadata.target_is_host_namespace == true &&
event.metadata.succeeded == true
```

### 4.2 危险挂载或根目录切换

需要 `security_sb_mount`/mount exit、`pivot_root`、`chroot`：

```cel
event.event_type in ["mount", "pivot_root", "chroot"] &&
event.container.container_id != "" &&
event.metadata.succeeded == true &&
(event.metadata.host_path == true || event.metadata.target_sensitive == true)
```

### 4.3 跨进程注入

需要 `ptrace`、`process_vm_writev`、`/proc/<pid>/mem` 的目标 PID、目标容器与请求类型：

```cel
event.event_type in ["ptrace", "process_vm_write"] &&
event.process.pid != event.metadata.target_pid &&
event.metadata.cross_security_boundary == true &&
event.metadata.succeeded == true
```

### 4.4 权限提升

需要调用前后 UID/GID、capability 集合及执行文件的 SUID/SGID/file-capability 属性：

```cel
event.event_type == "privilege_change" &&
event.metadata.succeeded == true &&
(event.metadata.uid_before != 0 && event.metadata.uid_after == 0 ||
 event.metadata.added_capabilities.exists(cap,
   cap in ["CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_BPF", "CAP_SYS_MODULE"]))
```

### 4.5 文件无落地或已删除文件执行

需要在执行成功点采集真实 inode/dentry，而不是只读取 `execve` 入参：

```cel
event.event_type == "process_exec" &&
event.metadata.succeeded == true &&
(event.metadata.memfd == true || event.metadata.deleted_inode == true)
```

### 4.6 内核攻击面修改

需要 BPF LSM/kprobe 采集 `bpf`、`init_module`/`finit_module` 和关键 procfs/sysfs 写入：

```cel
event.event_type in ["bpf_prog_load", "kernel_module_load", "kernel_control_write"] &&
event.metadata.succeeded == true &&
event.metadata.trusted_actor == false
```

### 4.7 容器运行时套接字访问

当前 connect Hook 只解析 AF_INET/AF_INET6；应增加 AF_UNIX 路径：

```cel
event.event_type == "unix_connect" &&
event.container.container_id != "" &&
event.metadata.socket_path in [
  "/var/run/docker.sock",
  "/run/containerd/containerd.sock",
  "/var/run/crio/crio.sock"
]
```

## 5. 实现约束与降噪要求

1. **只在成功事件上做高置信告警。** 当前 `execve/openat/connect/fchmodat/unlinkat` 多数在 syscall enter 采集，只能表示“尝试”，不能证明成功。下一版应关联 syscall exit，增加 `succeeded`、`errno`、`return_value`。
2. **路径必须规范化。** 需要处理相对路径、`dirfd`、符号链接、mount namespace 和容器根文件系统，否则敏感路径规则既可误报也可绕过。
3. **黑名单规则内置例外。** 当前策略固定先执行全部 blacklist，再执行 whitelist，因此 whitelist 无法覆盖已命中的 blacklist。包管理器、镜像构建、节点运维、日志轮转等例外必须写入 blacklist 条件本身，或后续修改为显式的 allow-override 语义。
4. **完整命令行。** 当前 Sensor 只保留 `argv[0]`、`argv[1]`，Netcat/凭据搜索规则可能漏报；建议受限采集前 N 个参数与总字节数，并做敏感参数脱敏。
5. **状态规则放在 Go 层。** CEL 只做确定性的单事件分类；时间窗、进程树、同实体序列和基线偏差由行为引擎处理。
6. **敏感读取不默认全量上报。** `file_open` 仅在 WATCH/INVESTIGATION 模式进入用户态，高频访问应本地聚合或作为告警上下文回捞。

## 6. 推荐实施顺序

1. 先验证候选 CEL 规则的命中率与误报率，不直接覆盖生产规则。
2. 增加 syscall exit 成功状态和路径规范化。
3. 增加 AF_UNIX、namespace、mount、privilege、ptrace/process_vm、memfd/deleted-exec 事件。
4. 建立规则测试集：每条规则至少一个正例、一个边界例、一个可信运维反例。
5. 将规则分为 `stable`、`incubating`、`sandbox`，只有 stable 默认启用。
