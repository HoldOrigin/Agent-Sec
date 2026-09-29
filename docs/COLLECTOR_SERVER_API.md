# Collector → Server 事件与告警协议

## 链路

```text
eBPF Ring Buffer
  → Collector Transform
  → CEL/内置规则检测
  → UploadPolicy 分级过滤与上下文提升
  → POST /api/collector/batch {events[], alerts[]}
  → Server Processor / Behavior / Incident
  → PostgreSQL runtime_events / alerts / behaviors / incidents
```

Collector 不再只把“是否告警”藏在事件 metadata 中。规则命中时，同一批次包含：

1. 原始 RuntimeEvent，用于时间线、行为关联和溯源证据；
2. 独立结构化 Alert，用于直接展示、检索和触发调查。

Server 仍会从事件生成 `B900 LocalSecurityPolicyMatch`。Collector Alert 和 B900 使用相同的关联键 `B900:<event_id>`，Repository 会合并规则和证据，最终只保留一条告警。

## 上报接口

```http
POST /api/collector/batch
Content-Type: application/json
Content-Encoding: gzip  # 可选
```

请求示例：

```json
{
  "events": [
    {
      "event_id": "evt-001",
      "timestamp": "2026-09-27T08:00:00Z",
      "event_type": "process_exec",
      "host": {"host_id": "node-a", "boot_id": "boot-a"},
      "process": {"pid": 4242, "ppid": 100, "exe": "/tmp/payload", "argv": ["/tmp/payload"]},
      "container": {"container_id": "container-a"},
      "metadata": {
        "security_alert": true,
        "detection_rule_id": "LOCAL-TEMP-EXEC",
        "detection_severity": "critical",
        "detection_reason": "temporary path execution"
      }
    }
  ],
  "alerts": [
    {
      "alert_id": "alt-collector-...",
      "title": "Collector local detection: LOCAL-TEMP-EXEC",
      "description": "temporary path execution",
      "severity": "critical",
      "source": "collector",
      "host_id": "node-a",
      "container_id": "container-a",
      "rule_ids": ["LOCAL-TEMP-EXEC"],
      "event_ids": ["evt-001"],
      "event_id": "evt-001",
      "correlation_key": "B900:evt-001",
      "status": "open",
      "created_at": "2026-09-27T08:00:00Z",
      "updated_at": "2026-09-27T08:00:00Z"
    }
  ]
}
```

Server 要求 Alert 引用的 `event_id` 已在当前批次或数据库中存在，拒绝没有原始证据的孤立告警。批次响应会分别返回事件接收数、入库数、告警接收数、告警入库数，以及派生 Behavior/Incident 数量。

## 查询接口

| 方法 | 路径 | 说明 |
|---|---|---|
| `GET` | `/api/events` | 查询事件，默认最多返回最近 200 条 |
| `GET` | `/api/events/{event_id}` | 查询单个事件 |
| `GET` | `/api/alerts` | 查询告警，默认最多返回最近 200 条 |
| `GET` | `/api/alerts/{alert_id}` | 查询单个告警 |

事件列表支持：

```text
type, host_id, container_id, limit(1..1000)
```

告警列表支持：

```text
severity, status, source, host_id, container_id, limit(1..1000)
```

示例：

```bash
curl 'http://127.0.0.1:8080/api/events?type=process_exec&host_id=node-a&limit=100'
curl 'http://127.0.0.1:8080/api/alerts?severity=critical&status=open&source=collector'
curl 'http://127.0.0.1:8080/api/alerts/ALT_ID'
```

## 失败处理和边界

- Collector 对非 2xx、网络错误进行有限指数退避重试；批次始终使用稳定的 Event/Alert ID，因此重试是幂等的。
- Server 先校验、标准化并写 PostgreSQL；写入失败返回非 2xx，Collector 不把该批次计入 submitted 指标。
- 当前批次不是跨 Event、Behavior、Alert、Incident 的单一数据库事务。中途失败可能已经写入部分事件，稳定 ID 保证重试时使用 upsert/去重继续完成。
- 当前 HTTP 通道尚未实现 mTLS 和 Collector 身份认证。生产环境不得把 `/api/collector/batch` 暴露到不可信网络。
- Processor 可能过滤重复或低价值事件；结构化告警只有在其证据事件已经存在时才会被接受。
