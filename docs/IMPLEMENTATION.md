# Go 基础框架实现说明

## 应用边界

`internal/app.Service` 是应用层入口，负责装配并协调：

```text
Ingest(input)
  → processor.Process
  → store.AddEvent
  → behavior.Derive
  → collection.ObserveBehaviors
  → incident.Correlate
  → collection.ObserveIncidents
  → investigation.Investigate
```

HTTP、Replay CLI 和测试不直接跨层调用检测实现。

## 并发与状态

- Memory Store 使用 `sync.RWMutex`。
- Event Processor 和动态采集 Manager 使用独立互斥锁。
- 每个 `app.Service` 实例拥有独立状态，测试和多实例之间不会泄漏事件。
- Event ID 和 Behavior correlation key 用于幂等去重。

## 错误契约

```json
{
  "error": {
    "code": "REQUEST_FAILED",
    "message": "Missing event fields: event_id",
    "request_id": "..."
  }
}
```

响应包含 `x-request-id`，方便后续与结构化日志关联。

## 可替换边界

| 当前实现 | 后续实现 |
|---|---|
| `store.Memory` | PostgreSQL Repository |
| `cmd/replay` | Linux `cilium/ebpf` Ring Buffer Collector |
| `policy.Engine` | OPA REST Adapter |
| 确定性调查归纳 | LLM Structured Output Adapter |
| 内存 Runtime Graph | PostgreSQL 关系表或图数据库 |

Repository 替换必须保证：

- Event ID 幂等写入
- Host/Container/时间范围查询
- ProcessEntityID 生命周期查询
- Behavior Evidence 外键完整性
- Incident 与 Behavior 多对多关系

## 基础指标

`GET /metrics` 暴露：

- `runtime_events_received_total`
- `runtime_events_accepted_total`
- `runtime_events_filtered_total`
- `runtime_events_deduplicated_total`
- `runtime_file_events_promoted_total`
- `runtime_behaviors`
- `runtime_incidents`
- 各动态采集级别 Scope 数量

## 下一阶段

1. 实现 Linux `cilium/ebpf` Collector 和 Ring Buffer 丢失事件指标。
2. 定义 Repository Interface，增加 PostgreSQL migration。
3. 将 Behavior Engine 改为增量计算并加入乱序缓冲。
4. 增加 Pipeline 延迟、调查耗时和错误率指标。
5. 接入 LLM 时使用固定 JSON Schema，并在返回前校验所有 Evidence ID。
6. 生产部署前加入认证、租户隔离、RBAC、审计日志和 TLS。
