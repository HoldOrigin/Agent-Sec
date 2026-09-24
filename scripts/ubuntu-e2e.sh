#!/usr/bin/env bash
# Agent-Sec Ubuntu end-to-end acceptance test.
#
# Usage:
#   bash scripts/ubuntu-e2e.sh
#   SKIP_EBPF=1 bash scripts/ubuntu-e2e.sh
#   RUN_AI=0 bash scripts/ubuntu-e2e.sh
#   AI_STRICT=0 bash scripts/ubuntu-e2e.sh
#
# Environment:
#   SERVER_HOST=127.0.0.1       Server listen host.
#   SERVER_PORT=18080           Server listen port.
#   METRICS_HOST=127.0.0.1      Collector metrics listen host.
#   METRICS_PORT=19091          Collector metrics port.
#   SKIP_EBPF=0                 Set to 1 to skip sensor build/load and hook tests.
#   RUN_AI=auto                 auto, 1, or 0. auto runs only when QWEN_API_KEY exists.
#   AI_STRICT=1                 Require evidence and SUSPICIOUS classification.
#   AI_TIMEOUT_SECONDS=240      Maximum AI HTTP request time.
#   KEEP_PROCESSES=0            Set to 1 to leave Server/Collector running after success.
#   ARTIFACT_DIR=<path>         Logs and JSON results; defaults under .artifacts/.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

SERVER_HOST="${SERVER_HOST:-127.0.0.1}"
SERVER_PORT="${SERVER_PORT:-18080}"
METRICS_HOST="${METRICS_HOST:-127.0.0.1}"
METRICS_PORT="${METRICS_PORT:-19091}"
SKIP_EBPF="${SKIP_EBPF:-0}"
RUN_AI="${RUN_AI:-auto}"
AI_STRICT="${AI_STRICT:-1}"
AI_TIMEOUT_SECONDS="${AI_TIMEOUT_SECONDS:-240}"
KEEP_PROCESSES="${KEEP_PROCESSES:-0}"
RUN_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
ARTIFACT_DIR="${ARTIFACT_DIR:-${REPO_ROOT}/.artifacts/e2e-${RUN_STAMP}}"
BASE_URL="http://${SERVER_HOST}:${SERVER_PORT}"
METRICS_URL="http://${METRICS_HOST}:${METRICS_PORT}/metrics"

SERVER_PID=""
COLLECTOR_PID=""
HOOK_FILE=""
TEST_FAILED=0
PASSED_STEPS=0
SKIPPED_STEPS=0
SUDO=()

mkdir -p "${ARTIFACT_DIR}"

if [[ -t 1 ]]; then
    GREEN=$'\033[32m'
    YELLOW=$'\033[33m'
    RED=$'\033[31m'
    RESET=$'\033[0m'
else
    GREEN=""
    YELLOW=""
    RED=""
    RESET=""
fi

log()  { printf '%s | %s\n' "$(date -u +%FT%TZ)" "$*"; }
pass() { PASSED_STEPS=$((PASSED_STEPS + 1)); log "${GREEN}PASS${RESET} | $*"; }
skip() { SKIPPED_STEPS=$((SKIPPED_STEPS + 1)); log "${YELLOW}SKIP${RESET} | $*"; }
die()  { TEST_FAILED=1; log "${RED}FAIL${RESET} | $*" >&2; exit 1; }

show_help() {
    awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "缺少命令: $1"
}

wait_http() {
    local url="$1"
    local owner_pid="${2:-}"
    local attempts="${3:-80}"
    local index
    for ((index = 1; index <= attempts; index++)); do
        if curl --noproxy '*' --connect-timeout 1 --max-time 2 -fsS "$url" >/dev/null 2>&1; then
            return 0
        fi
        if [[ -n "$owner_pid" ]] && ! kill -0 "$owner_pid" 2>/dev/null; then
            return 1
        fi
        sleep 0.25
    done
    return 1
}

stop_process() {
    local pid="$1"
    local privileged="$2"
    [[ -z "$pid" ]] && return 0
    if ! kill -0 "$pid" 2>/dev/null; then
        return 0
    fi
    if [[ "$privileged" == "1" ]]; then
        "${SUDO[@]}" kill -INT "$pid" 2>/dev/null || true
    else
        kill -INT "$pid" 2>/dev/null || true
    fi
    local index
    for ((index = 1; index <= 25; index++)); do
        kill -0 "$pid" 2>/dev/null || return 0
        sleep 0.2
    done
    if [[ "$privileged" == "1" ]]; then
        "${SUDO[@]}" kill -TERM "$pid" 2>/dev/null || true
    else
        kill -TERM "$pid" 2>/dev/null || true
    fi
}

cleanup() {
    local exit_code=$?
    if [[ "$exit_code" -ne 0 ]]; then
        TEST_FAILED=1
    fi
    if [[ "$KEEP_PROCESSES" != "1" || "$TEST_FAILED" == "1" ]]; then
        stop_process "$COLLECTOR_PID" 1
        stop_process "$SERVER_PID" 0
    fi
    if [[ -n "$HOOK_FILE" && -f "$HOOK_FILE" ]]; then
        rm -f -- "$HOOK_FILE"
    fi
    log "RESULT | passed=${PASSED_STEPS} skipped=${SKIPPED_STEPS} failed=${TEST_FAILED} artifacts=${ARTIFACT_DIR}"
    if [[ "$TEST_FAILED" == "1" ]]; then
        [[ -f "${ARTIFACT_DIR}/server.log" ]] && tail -n 30 "${ARTIFACT_DIR}/server.log" >&2 || true
        [[ -f "${ARTIFACT_DIR}/collector.log" ]] && tail -n 50 "${ARTIFACT_DIR}/collector.log" >&2 || true
    fi
}
trap cleanup EXIT
trap 'die "脚本在第 ${LINENO} 行失败"' ERR

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    trap - EXIT ERR
    show_help
    exit 0
fi

case "$SKIP_EBPF" in 0|1) ;; *) die "SKIP_EBPF 必须是 0 或 1" ;; esac
case "$RUN_AI" in auto|0|1) ;; *) die "RUN_AI 必须是 auto、0 或 1" ;; esac
case "$AI_STRICT" in 0|1) ;; *) die "AI_STRICT 必须是 0 或 1" ;; esac
case "$KEEP_PROCESSES" in 0|1) ;; *) die "KEEP_PROCESSES 必须是 0 或 1" ;; esac

require_command go
require_command make
require_command curl
require_command python3

if [[ "$SKIP_EBPF" == "0" ]]; then
    [[ "$(uname -s)" == "Linux" ]] || die "真实 eBPF 测试只能在 Linux 运行；可设置 SKIP_EBPF=1"
    require_command clang
    require_command bpftool
    [[ -r /sys/kernel/btf/vmlinux ]] || die "当前内核未暴露 /sys/kernel/btf/vmlinux"
    if [[ "$EUID" -ne 0 ]]; then
        require_command sudo
        sudo -v || die "eBPF 加载需要 sudo 权限"
        SUDO=(sudo)
    fi
fi

log "START | repo=${REPO_ROOT} artifacts=${ARTIFACT_DIR}"
go version | tee "${ARTIFACT_DIR}/go-version.txt"
uname -a | tee "${ARTIFACT_DIR}/uname.txt"

log "STEP | Go 单元测试"
make test 2>&1 | tee "${ARTIFACT_DIR}/go-test.log"
pass "go test ./..."

log "STEP | Go 静态检查"
make vet 2>&1 | tee "${ARTIFACT_DIR}/go-vet.log"
pass "go vet ./..."

if [[ "$SKIP_EBPF" == "0" ]]; then
    log "STEP | 编译 CO-RE eBPF 对象"
    make sensor 2>&1 | tee "${ARTIFACT_DIR}/sensor-build.log"
    [[ -s sensor/ebpf/runtime.bpf.o ]] || die "未生成 sensor/ebpf/runtime.bpf.o"
    pass "eBPF object 编译成功"
else
    skip "eBPF 编译和加载测试"
fi

log "STEP | 编译 Go 可执行文件"
make build 2>&1 | tee "${ARTIFACT_DIR}/go-build.log"
[[ -x bin/sentinel && -x bin/replay ]] || die "Server 或 Replay 二进制不存在"
if [[ "$SKIP_EBPF" == "0" ]]; then
    [[ -x bin/sentinel-collector ]] || die "Collector 二进制不存在"
fi
pass "Go 二进制编译成功"

if curl --noproxy '*' --connect-timeout 1 --max-time 2 -fsS "${BASE_URL}/api/health" >/dev/null 2>&1; then
    die "${BASE_URL} 已被其他服务占用，请修改 SERVER_PORT"
fi

log "STEP | 启动 Server"
HOST="$SERVER_HOST" PORT="$SERVER_PORT" \
AI_AUDIT_LOG_PATH="${ARTIFACT_DIR}/ai-audit.jsonl" \
    ./bin/sentinel >"${ARTIFACT_DIR}/server.log" 2>&1 &
SERVER_PID=$!
if ! wait_http "${BASE_URL}/api/health" "$SERVER_PID"; then
    die "Server 启动失败"
fi
curl --noproxy '*' -fsS "${BASE_URL}/api/health" >"${ARTIFACT_DIR}/health.json"
pass "Server 健康检查"

log "STEP | Web RCE 正样本回放"
./bin/replay -url "$BASE_URL" -file datasets/web_rce.jsonl -reset -interval 0 \
    2>&1 | tee "${ARTIFACT_DIR}/positive-replay.log"
curl --noproxy '*' -fsS "${BASE_URL}/api/summary" >"${ARTIFACT_DIR}/positive-summary.json"
curl --noproxy '*' -fsS "${BASE_URL}/api/incidents" >"${ARTIFACT_DIR}/positive-incidents.json"
python3 - "${ARTIFACT_DIR}/positive-summary.json" "${ARTIFACT_DIR}/positive-incidents.json" <<'PY'
import json, sys
summary = json.load(open(sys.argv[1], encoding="utf-8"))
incidents = json.load(open(sys.argv[2], encoding="utf-8"))
expected = {"events": 6, "behaviors": 8, "alerts": 1, "incidents": 1, "critical": 1}
for key, value in expected.items():
    assert summary.get(key) == value, f"{key}={summary.get(key)!r}, expected={value!r}"
assert len(incidents) == 1, f"incident count={len(incidents)}"
incident = incidents[0]
assert incident.get("risk") == "critical", incident.get("risk")
assert incident.get("score") == 100, incident.get("score")
assert incident.get("classification") == "likely_compromise", incident.get("classification")
assert len(incident.get("evidence_event_ids", [])) == 6
PY
pass "正样本产生 6 Events、8 Behaviors、1 Critical Incident"

INCIDENT_ID="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))[0]["incident_id"])' "${ARTIFACT_DIR}/positive-incidents.json")"

SHOULD_RUN_AI=0
if [[ "$RUN_AI" == "1" ]]; then
    [[ -n "${QWEN_API_KEY:-}" ]] || die "RUN_AI=1 但没有设置 QWEN_API_KEY"
    SHOULD_RUN_AI=1
elif [[ "$RUN_AI" == "auto" && -n "${QWEN_API_KEY:-}" ]]; then
    SHOULD_RUN_AI=1
fi

if [[ "$SHOULD_RUN_AI" == "1" ]]; then
    log "STEP | Qwen Plan-and-Execute + ReAct 调查"
    printf '{"incident_id":"%s"}' "$INCIDENT_ID" >"${ARTIFACT_DIR}/ai-request.json"
    curl --noproxy '*' --max-time "$AI_TIMEOUT_SECONDS" -fsS \
        -X POST -H 'Content-Type: application/json' \
        --data-binary @"${ARTIFACT_DIR}/ai-request.json" \
        "${BASE_URL}/api/agent/investigate-ai" >"${ARTIFACT_DIR}/ai-result.json"
    python3 - "${ARTIFACT_DIR}/ai-result.json" "$AI_STRICT" <<'PY'
import json, sys
result = json.load(open(sys.argv[1], encoding="utf-8"))
strict = sys.argv[2] == "1"
assert result.get("run_id"), "missing run_id"
assert result.get("status") in {"COMPLETED", "NEEDS_REVIEW"}, result.get("status")
models = result.get("models", {})
for role in ("planner", "executor", "analyzer"):
    assert models.get(role) == "qwen3.7-plus", f"{role}={models.get(role)!r}"
assert len(result.get("plan", {}).get("tasks", [])) >= 1, "plan has no tasks"
assert len(result.get("tasks", {})) >= 1, "no task results"
if strict:
    assert len(result.get("evidence", {})) > 0, "AI returned zero evidence"
    assert result.get("report", {}).get("classification") == "SUSPICIOUS", result.get("report", {}).get("classification")
    evidence_ids = set(result.get("evidence", {}))
    for finding in result.get("report", {}).get("findings", []):
        if finding.get("type") == "OBSERVED":
            refs = finding.get("evidence_ids", [])
            assert refs and set(refs) <= evidence_ids, f"invalid evidence refs: {refs}"
PY
    [[ -s "${ARTIFACT_DIR}/ai-audit.jsonl" ]] || die "AI 审计日志为空"
    python3 - "${ARTIFACT_DIR}/ai-audit.jsonl" <<'PY'
import json, sys
events = [json.loads(line)["event"] for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
required = {"RUN_START", "PLAN_ACCEPTED", "TASK_START", "ACTION_SELECTED", "TOOL_START", "TOOL_END", "TASK_END", "RUN_END"}
missing = sorted(required - set(events))
assert not missing, f"missing audit events: {missing}"
PY
    pass "AI 调查结构、证据约束和审计链路"
else
    skip "AI 调查；设置 QWEN_API_KEY 且 RUN_AI=auto/1 可启用"
fi

log "STEP | 正常操作负样本回放"
./bin/replay -url "$BASE_URL" -file datasets/normal_ops.jsonl -reset -interval 0 \
    2>&1 | tee "${ARTIFACT_DIR}/negative-replay.log"
curl --noproxy '*' -fsS "${BASE_URL}/api/summary" >"${ARTIFACT_DIR}/negative-summary.json"
python3 - "${ARTIFACT_DIR}/negative-summary.json" <<'PY'
import json, sys
summary = json.load(open(sys.argv[1], encoding="utf-8"))
expected = {"events": 2, "behaviors": 1, "alerts": 0, "incidents": 0, "critical": 0}
for key, value in expected.items():
    assert summary.get(key) == value, f"{key}={summary.get(key)!r}, expected={value!r}"
PY
pass "负样本不生成 Alert 或 Incident"

if [[ "$SKIP_EBPF" == "0" ]]; then
    log "STEP | 启动 eBPF Collector"
    curl --noproxy '*' -fsS -X POST -H 'Content-Type: application/json' -d '{}' \
        "${BASE_URL}/api/reset" >"${ARTIFACT_DIR}/pre-ebpf-reset.json"
    "${SUDO[@]}" ./bin/sentinel-collector \
        -object sensor/ebpf/runtime.bpf.o \
        -server "$BASE_URL" \
        -metrics "${METRICS_HOST}:${METRICS_PORT}" \
        -batch-size 20 \
        -flush-interval 250ms \
        -high-flush-interval 100ms \
        -aggregate-window 2s \
        -on-alert-buffer-ttl 30s \
        >"${ARTIFACT_DIR}/collector.log" 2>&1 &
    COLLECTOR_PID=$!
    if ! wait_http "$METRICS_URL" "$COLLECTOR_PID" 120; then
        die "Collector 启动或 BPF verifier/load 失败"
    fi
    pass "Collector 加载 eBPF 并暴露指标"

    log "STEP | 触发 exec/open/chmod/unlink/connect Hook"
    HOOK_FILE="$(mktemp /tmp/agent-sec-e2e.XXXXXX)"
    /bin/true
    chmod 750 "$HOOK_FILE"
    curl --noproxy '*' --connect-timeout 2 --max-time 5 -fsS "${BASE_URL}/api/health" >/dev/null
    rm -f -- "$HOOK_FILE"
    HOOK_FILE=""
    sleep 4

    curl --noproxy '*' -fsS "$METRICS_URL" >"${ARTIFACT_DIR}/collector-metrics.txt"
    curl --noproxy '*' -fsS "${BASE_URL}/api/summary" >"${ARTIFACT_DIR}/ebpf-summary.json"
    python3 - "${ARTIFACT_DIR}/collector-metrics.txt" <<'PY'
import re, sys
text = open(sys.argv[1], encoding="utf-8").read()
def metric(name):
    match = re.search(rf"^{re.escape(name)}\s+([0-9.eE+-]+)$", text, re.MULTILINE)
    assert match, f"missing metric {name}"
    return float(match.group(1))
assert metric("sentinel_collector_samples_total") > 0
assert metric("sentinel_collector_events_transformed_total") > 0
assert metric("sentinel_ebpf_events_emitted_total") > 0
assert metric("sentinel_collector_decode_errors_total") == 0
assert metric("sentinel_collector_send_errors_total") == 0
reserve_failed = metric("sentinel_ebpf_ringbuf_reserve_failed_total")
assert reserve_failed == 0, f"ring buffer reserve failures={reserve_failed}"
PY
    pass "真实 Hook 事件进入 Ring Buffer、完成解码且无丢失"
else
    skip "真实 eBPF Hook、Ring Buffer 和 Collector 指标测试"
fi

if [[ "$KEEP_PROCESSES" == "1" ]]; then
    log "INFO | KEEP_PROCESSES=1 server_pid=${SERVER_PID} collector_pid=${COLLECTOR_PID:-none}"
fi

log "SUCCESS | Agent-Sec 端到端验收完成"
