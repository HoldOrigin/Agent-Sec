# PostgreSQL 持久化设计与使用

## 目标

Agent-Sec Server 默认要求配置 PostgreSQL。事件、行为、告警和 Incident 写库成功后才向调用方返回成功。服务重启时会加载数据库快照，因此告警和溯源证据不会因进程退出而丢失。只有显式设置 `ALLOW_IN_MEMORY_STORAGE=true` 时才允许本地临时内存模式。

## 数据流

```text
eBPF Collector → POST /api/collector/batch (events[] + alerts[]) → Processor
  → runtime_events(JSONB)
  → Behavior Engine → behaviors(JSONB)
  → Alert/Incident Correlation → alerts/incidents(JSONB)
  → 内存查询快照 → REST API / Investigation Agent / AI Agent
```

PostgreSQL 是持久化事实源，内存快照用于 MVP 的低延迟关联和查询。每张表同时保存：

- 完整 `payload JSONB`：保证 Go 领域模型可以无损恢复；
- 常用索引列：时间、主机、容器、进程、严重级别、状态和关联键；
- `stored_at`：记录最近写入时间。

Schema 位于 `internal/store/schema.sql`，Server 启动时幂等执行 `CREATE TABLE/INDEX IF NOT EXISTS`。生产环境后续应改用有版本号的迁移工具，而不是无限扩展启动迁移。

## Ubuntu 本地运行

创建数据库和用户（密码请自行替换）：

```bash
sudo -u postgres psql <<'SQL'
CREATE USER sentinel WITH PASSWORD 'change-me';
CREATE DATABASE sentinel OWNER sentinel;
SQL

export DATABASE_URL='postgres://sentinel:change-me@127.0.0.1:5432/sentinel?sslmode=disable'
make run
```

启动日志应包含：

```text
storage=postgresql
```

健康检查：

```bash
curl -s http://127.0.0.1:8080/api/health | jq .components.storage
```

预期：

```json
{"backend":"postgresql","durable":true}
```

不设置 `DATABASE_URL` 时 Server 默认拒绝启动。仅本地临时调试可以显式执行：

```bash
export ALLOW_IN_MEMORY_STORAGE=true
make run
```

该模式不具备重启恢复能力，不能用于 Collector 联调、演示验收或生产部署。

## Docker Compose

```bash
docker compose up --build
```

Compose 会启动 PostgreSQL 17，等待健康检查通过后再启动 Server，并使用具名卷 `postgres-data` 保存数据。Compose 中的 `sentinel/sentinel` 仅用于本地开发，不能用于生产。

## 配置

| 环境变量 | 默认值 | 说明 |
|---|---:|---|
| `DATABASE_URL` | 必填 | PostgreSQL DSN；Server 默认要求配置 |
| `ALLOW_IN_MEMORY_STORAGE` | `false` | 仅供本地临时开发的显式逃生开关 |
| `DATABASE_MAX_OPEN_CONNS` | `10` | 最大打开连接数 |
| `DATABASE_MAX_IDLE_CONNS` | `5` | 最大空闲连接数 |
| `DATABASE_TIMEOUT_SECONDS` | `5` | 连接、迁移和单次写操作超时 |

生产环境必须启用 TLS（不要使用 `sslmode=disable`），通过 Secret 注入凭据，并限制数据库账号只能访问 Agent-Sec 自己的数据库。

## 验证持久化

1. 启动 PostgreSQL 和 Server。
2. 回放数据：`go run ./cmd/replay -file datasets/web_rce.jsonl -reset`。
3. 检查表：

```bash
psql "$DATABASE_URL" -c 'select count(*) from runtime_events;'
psql "$DATABASE_URL" -c 'select alert_id,severity,status from alerts;'
psql "$DATABASE_URL" -c 'select incident_id,severity,status from incidents;'
```

4. 重启 Server，再访问 `/api/events`、`/api/alerts`、`/api/incidents`，记录应仍存在。

集成测试会清空 Agent-Sec 四张表，只能指向一次性测试库：

```bash
export TEST_DATABASE_URL='postgres://sentinel:sentinel@127.0.0.1:5432/sentinel_test?sslmode=disable'
make test-postgres
```

`POST /api/reset` 在 PostgreSQL 模式下会清空四张业务表；这是演示和测试接口，不应对生产调用者开放。

## 当前 MVP 边界

- 读取通过启动时恢复的内存快照完成，不是每次请求查询 PostgreSQL；同一个数据库不能由多个 Server 实例同时写入。
- `behaviors` 是当前全部事件的派生视图，每次 Pipeline 会在事务中整体替换。
- 尚未实现数据保留期、分区、冷热分层、租户隔离和归档。
- AI Agent 的模型调用审计仍写 JSONL；确定性调查完成后的 Incident 已写入 PostgreSQL。AI 调查运行记录可以在下一阶段独立建表，避免把模型过程日志混入安全事实表。
