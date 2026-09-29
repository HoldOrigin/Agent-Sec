#!/usr/bin/env bash
set -Eeuo pipefail

# End-to-end validation for an isolated Ubuntu test host:
# safe signal generator -> eBPF -> RingBuffer -> Go collector -> CEL alert ->
# behavior/incident correlation -> Qwen Plan-and-Execute/ReAct investigation.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_PORT="${AGENT_SEC_E2E_PORT:-18080}"
METRICS_PORT="${AGENT_SEC_E2E_METRICS_PORT:-19091}"
SERVER_URL="http://127.0.0.1:${SERVER_PORT}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
ARTIFACT_DIR="${ROOT_DIR}/.artifacts/e2e-${RUN_ID}"
SKIP_AI=0

if [[ "${1:-}" == "--skip-ai" ]]; then
  SKIP_AI=1
elif [[ $# -gt 0 ]]; then
  echo "usage: sudo -E bash scripts/e2e_ebpf_ai_demo.sh [--skip-ai]" >&2
  exit 2
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "E2E eBPF validation requires Linux." >&2
  exit 2
fi
if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root so the collector can load eBPF: sudo -E bash scripts/e2e_ebpf_ai_demo.sh" >&2
  exit 2
fi
if [[ ${SKIP_AI} -eq 0 && -z "${QWEN_API_KEY:-}" ]]; then
  echo "QWEN_API_KEY is required for the real AI stage; use --skip-ai only for sensor/pipeline validation." >&2
  exit 2
fi
for command in go make clang bpftool curl python3; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "missing required command: ${command}" >&2
    exit 2
  fi
done
if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
  echo "/sys/kernel/btf/vmlinux is unavailable; CO-RE build cannot continue." >&2
  exit 2
fi

mkdir -p "${ARTIFACT_DIR}" "${ROOT_DIR}/bin/demo"
SERVER_PID=""
COLLECTOR_PID=""

cleanup() {
  set +e
  if [[ -n "${COLLECTOR_PID}" ]]; then kill "${COLLECTOR_PID}" 2>/dev/null; wait "${COLLECTOR_PID}" 2>/dev/null; fi
  if [[ -n "${SERVER_PID}" ]]; then kill "${SERVER_PID}" 2>/dev/null; wait "${SERVER_PID}" 2>/dev/null; fi
  if [[ -d /tmp/agent-sec-demo && ! -L /tmp/agent-sec-demo && -f /tmp/agent-sec-demo/.agent-sec-safe-demo ]] &&
     [[ "$(cat /tmp/agent-sec-demo/.agent-sec-safe-demo 2>/dev/null)" == "agent-sec-safe-demo-v1" ]]; then
    if [[ -f /tmp/agent-sec-demo/payload && ! -L /tmp/agent-sec-demo/payload ]]; then rm -f -- /tmp/agent-sec-demo/payload; fi
    rm -f -- /tmp/agent-sec-demo/.agent-sec-safe-demo
    rmdir -- /tmp/agent-sec-demo 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

cd "${ROOT_DIR}"
echo "[1/8] build Go services, safe signal generator and eBPF object"
go test ./... >"${ARTIFACT_DIR}/go-test.log" 2>&1
go build -trimpath -o bin/sentinel ./cmd/server
go build -trimpath -o bin/sentinel-collector ./cmd/collector
go build -trimpath -o bin/demo/demo-payload ./cmd/demo-payload
cp -- bin/demo/demo-payload bin/demo/java
cp -- bin/demo/demo-payload bin/demo/curl
chmod 0755 bin/demo/java bin/demo/curl
make -C sensor/ebpf >"${ARTIFACT_DIR}/ebpf-build.log" 2>&1

echo "[2/8] start Sentinel server"
HOST=127.0.0.1 \
PORT="${SERVER_PORT}" \
AI_AUDIT_LOG_PATH="${ARTIFACT_DIR}/ai-audit.jsonl" \
QWEN_API_KEY="${QWEN_API_KEY:-}" \
QWEN_PLANNER_MODEL="${QWEN_PLANNER_MODEL:-qwen3.7-plus}" \
QWEN_EXECUTOR_MODEL="${QWEN_EXECUTOR_MODEL:-qwen3.7-plus}" \
QWEN_ANALYZER_MODEL="${QWEN_ANALYZER_MODEL:-qwen3.7-plus}" \
./bin/sentinel -root "${ROOT_DIR}" >"${ARTIFACT_DIR}/server.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 50); do
  if curl -fsS "${SERVER_URL}/api/health" >"${ARTIFACT_DIR}/health.json" 2>/dev/null; then break; fi
  if ! kill -0 "${SERVER_PID}" 2>/dev/null; then
    echo "server exited during startup" >&2
    tail -n 80 "${ARTIFACT_DIR}/server.log" >&2
    exit 1
  fi
  sleep 0.1
done
curl -fsS "${SERVER_URL}/api/health" >"${ARTIFACT_DIR}/health.json"

echo "[3/8] start eBPF collector with CEL detection"
./bin/sentinel-collector \
  -object sensor/ebpf/runtime.bpf.o \
  -server "${SERVER_URL}" \
  -metrics "127.0.0.1:${METRICS_PORT}" \
  -batch-size 1 \
  -flush-interval 100ms \
  -high-flush-interval 20ms \
  -aggregate-window 1s \
  -post-alert-window 30s \
  -detection-rules configs/detection-rules.yaml \
  -exclude-pids "${SERVER_PID}" >"${ARTIFACT_DIR}/collector.log" 2>&1 &
COLLECTOR_PID=$!

for _ in $(seq 1 50); do
  if curl -fsS "http://127.0.0.1:${METRICS_PORT}/metrics" >"${ARTIFACT_DIR}/collector-metrics-before.txt" 2>/dev/null; then break; fi
  if ! kill -0 "${COLLECTOR_PID}" 2>/dev/null; then
    echo "collector exited during startup" >&2
    tail -n 80 "${ARTIFACT_DIR}/collector.log" >&2
    exit 1
  fi
  sleep 0.1
done
curl -fsS "http://127.0.0.1:${METRICS_PORT}/metrics" >"${ARTIFACT_DIR}/collector-metrics-before.txt"

echo "[4/8] execute fixed non-destructive attack-signal chain"
AGENT_SEC_DEMO=1 ./bin/demo/java --run-safe-demo | tee "${ARTIFACT_DIR}/payload.log"

json_count() {
  local endpoint="$1"
  curl -fsS "${SERVER_URL}${endpoint}" 2>/dev/null | python3 -c 'import json,sys; value=json.load(sys.stdin); print(len(value) if isinstance(value,list) else 0)' 2>/dev/null || echo 0
}

echo "[5/8] wait for events, alerts and incident correlation"
for _ in $(seq 1 100); do
  events="$(json_count /api/events)"
  alerts="$(json_count /api/alerts)"
  incidents="$(json_count /api/incidents)"
  if [[ "${events}" -ge 5 && "${alerts}" -ge 1 && "${incidents}" -ge 1 ]]; then break; fi
  sleep 0.2
done
curl -fsS "${SERVER_URL}/api/events" >"${ARTIFACT_DIR}/events.json"
curl -fsS "${SERVER_URL}/api/behaviors" >"${ARTIFACT_DIR}/behaviors.json"
curl -fsS "${SERVER_URL}/api/alerts" >"${ARTIFACT_DIR}/alerts.json"
curl -fsS "${SERVER_URL}/api/incidents" >"${ARTIFACT_DIR}/incidents.json"
curl -fsS "http://127.0.0.1:${METRICS_PORT}/metrics" >"${ARTIFACT_DIR}/collector-metrics-after.txt"

python3 -c '
import json, pathlib, sys
root=pathlib.Path(sys.argv[1])
events=json.loads((root/"events.json").read_text())
behaviors=json.loads((root/"behaviors.json").read_text())
alerts=json.loads((root/"alerts.json").read_text())
incidents=json.loads((root/"incidents.json").read_text())
event_types={e.get("event_type") or e.get("type") for e in events}
behavior_types={b.get("type") for b in behaviors}
required_events={"process_exec","file_create","file_chmod","network_connect"}
required_behaviors={"WebServerSpawnShell","DownloadExecutable","ExecuteFromTemp","RareExternalConnection"}
missing_events=required_events-event_types
missing_behaviors=required_behaviors-behavior_types
if missing_events or missing_behaviors or not alerts or not incidents:
    raise SystemExit(f"pipeline validation failed: missing_events={missing_events}, missing_behaviors={missing_behaviors}, alerts={len(alerts)}, incidents={len(incidents)}")
print(f"pipeline PASS: events={len(events)} behaviors={len(behaviors)} alerts={len(alerts)} incidents={len(incidents)}")
' "${ARTIFACT_DIR}"

INCIDENT_ID="$(python3 -c 'import json,sys; values=json.load(open(sys.argv[1])); print(values[0]["incident_id"])' "${ARTIFACT_DIR}/incidents.json")"
echo "[6/8] correlated incident: ${INCIDENT_ID}"

if [[ ${SKIP_AI} -eq 0 ]]; then
  echo "[7/8] automatically trigger Qwen AI-Agent investigation"
  python3 -c 'import json,sys; print(json.dumps({"incident_id":sys.argv[1]}))' "${INCIDENT_ID}" >"${ARTIFACT_DIR}/ai-request.json"
  curl -fsS --max-time 180 -X POST -H 'content-type: application/json' --data-binary "@${ARTIFACT_DIR}/ai-request.json" "${SERVER_URL}/api/agent/investigate-ai" >"${ARTIFACT_DIR}/ai-result.json"
  python3 -c '
import json, pathlib, sys
root=pathlib.Path(sys.argv[1])
result=json.loads((root/"ai-result.json").read_text())
if not result.get("run_id") or result.get("status") not in {"COMPLETED","NEEDS_REVIEW"}:
    raise SystemExit(f"AI investigation did not complete safely: {result}")
plan=result.get("plan",{}).get("tasks",[])
if not plan or not result.get("tasks"):
    raise SystemExit("AI investigation did not produce a plan and task results")
audit=root/"ai-audit.jsonl"
text=audit.read_text() if audit.exists() else ""
if "RUN_START" not in text or "RUN_END" not in text or "TOOL_OBSERVATION" not in text:
    raise SystemExit("AI audit chain is incomplete")
print("AI PASS: run={} status={} classification={}".format(result["run_id"], result["status"], result.get("report",{}).get("classification")))
' "${ARTIFACT_DIR}"
else
  echo "[7/8] AI stage skipped by explicit --skip-ai"
fi

echo "[8/8] E2E PASS"
echo "Artifacts: ${ARTIFACT_DIR}"
echo "  eBPF metrics: ${ARTIFACT_DIR}/collector-metrics-after.txt"
echo "  captured events: ${ARTIFACT_DIR}/events.json"
echo "  alerts/incidents: ${ARTIFACT_DIR}/alerts.json, ${ARTIFACT_DIR}/incidents.json"
if [[ ${SKIP_AI} -eq 0 ]]; then
  echo "  AI result/audit: ${ARTIFACT_DIR}/ai-result.json, ${ARTIFACT_DIR}/ai-audit.jsonl"
fi
