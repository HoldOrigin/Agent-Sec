# Sentinel — Go eBPF Runtime Behavior Graph MVP

基于 Go 实现的 Web RCE 运行时行为图谱检测 MVP：

```text
eBPF facts / JSONL Replay
  → Event Processor
  → 8 Behavior Primitives
  → Runtime Behavior Graph
  → 5-minute Incident Correlation
  → Investigation Agent
  → Evidence-bound Attack Story
```

本期只验证：Web 服务派生 Shell，下载未知程序到临时目录，修改执行权限并运行，随后连接罕见公网地址。

## 技术栈

- 后端、规则、关联、调查编排：Go 1.26
- HTTP：Go 标准库 `net/http`
- 存储：线程安全内存 Repository，已预留 PostgreSQL 替换边界
- Sensor：Linux CO-RE eBPF + 8 MiB Ring Buffer + Go Collector
- Policy：Go 本地决策器及等价 Rego 策略
- UI：无构建依赖的静态 HTML/CSS/JavaScript
- Collector 依赖：`github.com/cilium/ebpf`；Server 仍仅使用 Go 标准库

## 本地启动

要求 Go 1.26 或更高版本。

```powershell
cd "F:\workspace\Agent-Sec"
go run ./cmd/server
```

当前机器的 Go 安装路径为：

```text
C:\Users\pc\Documents\Codex\tools\go1.26.5\go\bin
```

新终端会从用户 PATH 识别 `go`。当前终端若尚未刷新，可以使用完整路径：

```powershell
& "C:\Users\pc\Documents\Codex\tools\go1.26.5\go\bin\go.exe" run ./cmd/server
```

打开 <http://localhost:8080>。

## 构建与测试

为避免受限环境下 Go 默认缓存目录不可写，可以将缓存放在项目内：

```powershell
$env:GOCACHE = "$PWD\.cache\go-build"
$env:GOPATH = "$PWD\.cache\gopath"
go test ./...
go vet ./...
go build -trimpath -o bin\sentinel.exe ./cmd/server
go build -trimpath -o bin\replay.exe ./cmd/replay
```

Linux/macOS 可使用：

```bash
make test
make build
```

## JSONL Collector / Replay

启动服务后，在另一个终端执行：

```powershell
go run ./cmd/replay -file datasets/web_rce.jsonl -reset -interval 50ms
```

成功结果：

```text
6 Runtime Events
  → 8 Behaviors
  → 1 WebRCEPayloadExecution Incident
  → Critical / Score 100 / Confidence 98%
```

负样本：

```powershell
go run ./cmd/replay -file datasets/normal_ops.jsonl -reset
```

负样本只产生一个 `WebServerSpawnShell` Behavior，采集级别进入 `WATCH`，不会创建 Incident 或调用 Investigation Agent。

## Behavior 规则

| Code | Behavior | 分值 |
|---|---|---:|
| B001 | WebServerSpawnShell | 30 |
| B002 | ShellSpawnDownloader | 10 |
| B003 | DownloadExecutable | 15 |
| B004 | WriteExecutableToTemp | 10 |
| B005 | ChangeExecutablePermission | 10 |
| B006 | ExecuteFromTemp | 25 |
| B007 | UnknownBinaryExecution | 10 |
| B008 | RareExternalConnection | 20 |

Incident 必须在同一 Host/Container 和五分钟窗口中包含 B001、B003、B006、B008。风险分最高限制为 100。

## Go 项目结构

```text
cmd/
├── server/                 HTTP Server 入口
├── replay/                 JSONL Collector/Replay CLI
└── collector/              Linux eBPF Ring Buffer Collector

internal/
├── app/                    配置、应用装配、Pipeline Service
├── model/                  RuntimeEvent/Behavior/Incident 领域模型
├── store/                  线程安全 Memory Repository
├── processor/              Normalize/Filter/Deduplicate/Delay Cache
├── behavior/               8 个确定性 Behavior Primitive
├── graph/                  Runtime Behavior Graph
├── incident/               五分钟 Pattern Correlation
├── investigation/          Root Cause/Timeline/Blast Radius/Attack Story
├── policy/                 响应动作 Guardrail
├── collection/             NORMAL/WATCH/INVESTIGATION
└── httpapi/                REST API、错误和静态资源适配

sensor/ebpf/                Linux CO-RE eBPF Sensor、共享 ABI 与构建文件
public/                     Incident 调查控制台
datasets/                   攻击样本和负样本
opa/policies/               等价 Rego 策略
```

依赖方向保持：

```text
sensor → processor → behavior → graph → incident → investigation
```

HTTP 不包含检测逻辑，CLI、HTTP 和测试均调用同一个 `app.Service`。

## API

| 方法 | 路径 | 用途 |
|---|---|---|
| `POST` | `/api/events` | 接入单条 RuntimeEvent |
| `POST` | `/api/events/batch` | 批量接入并执行一次关联流水线 |
| `POST` | `/api/replay` | 回放内置攻击或负样本 |
| `GET` | `/api/events` | 查询已保留事实 |
| `GET` | `/api/behaviors` | 查询 Behavior 及 Evidence |
| `GET` | `/api/incidents` | 查询 Incident 和调查结果 |
| `GET` | `/api/incidents/{id}/graph` | 查询 Runtime 子图 |
| `GET` | `/api/collection-policies` | 查询动态采集级别 |
| `GET` | `/api/processor/stats` | 查询接收、过滤、去重和提升统计 |
| `POST` | `/api/agent/investigate` | 对已有 Incident 重新调查 |
| `POST` | `/api/actions/evaluate` | Policy Guardrail 决策 |
| `GET` | `/metrics` | Prometheus 格式基础指标 |

健康检查返回：

```json
{
  "status": "ok",
  "version": "0.4.0",
  "implementation": "go"
}
```

## 配置

| 环境变量 | 默认值 | 说明 |
|---|---:|---|
| `HOST` | `0.0.0.0` | HTTP 监听地址 |
| `PORT` | `8080` | HTTP 端口 |
| `BODY_LIMIT_BYTES` | `1000000` | 请求体大小限制 |
| `FILE_CACHE_TTL_SECONDS` | `60` | 文件延迟关联缓存 |
| `CORRELATION_WINDOW_SECONDS` | `300` | Incident 关联窗口 |
| `INVESTIGATION_WINDOW_SECONDS` | `120` | 动态采集窗口 |
| `MAX_AGENT_STEPS` | `10` | 调查工具调用上限，最低为 8 |

## Docker

```bash
docker compose up --build
```

Docker 使用 Go 多阶段构建，最终镜像仅包含静态 Go 二进制、UI、数据集和策略文件，并以非 root 用户运行。

## 当前边界

真实 eBPF 程序只能在 Linux 内核加载。本仓库已实现 CO-RE Sensor、稳定事件 ABI、内核过滤/采集等级 Map、Ring Buffer Reader、容器元数据补充、批量上报和丢事件指标。当前 Windows 环境已验证 Go 测试和 Linux Collector 交叉编译；BPF object 编译、内核 verifier 和负载测试仍需在 Linux CI/VM 完成。

详细设计和运行方法见 [`docs/EBPF_RING_BUFFER_DESIGN.md`](docs/EBPF_RING_BUFFER_DESIGN.md)。后续重点是 syscall enter/exit 成功语义、CRI 元数据缓存、服务端采集策略订阅和断网 WAL。
