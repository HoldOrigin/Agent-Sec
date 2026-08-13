const state = { dataset: 'web_rce', incidents: [], selectedId: null, tab: 'story' };
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

$$('.scenario-card').forEach((button) => button.addEventListener('click', () => {
  $$('.scenario-card').forEach((item) => item.classList.remove('selected'));
  button.classList.add('selected');
  state.dataset = button.dataset.dataset;
}));

$('#replayButton').addEventListener('click', replay);
$('#resetButton').addEventListener('click', reset);

async function replay() {
  const button = $('#replayButton');
  button.disabled = true;
  button.innerHTML = '<span>◌</span> Agent 调查中…';
  $('#replayStatus').textContent = '正在关联事件与上下文';
  try {
    const result = await api('/api/replay', { method: 'POST', body: { dataset: state.dataset, reset: true } });
    await refresh();
    state.selectedId = result.incidents[0]?.incident_id;
    renderIncidents();
    if (result.incidents[0]) renderDetail(result.incidents[0]);
    else renderNoIncident(result.behaviors || []);
    $('#replayStatus').textContent = `${result.events_ingested} 条事件 · ${result.behaviors_detected} 个 Behavior · ${result.incidents.length} 个 Incident`;
    toast(result.incidents.length ? '调查完成：所有结论已绑定事件证据' : '行为未满足攻击 Pattern，未生成 Incident');
  } catch (error) {
    toast(`回放失败：${error.message}`);
    $('#replayStatus').textContent = '回放失败';
  } finally {
    button.disabled = false;
    button.innerHTML = '<span>▶</span> 回放并自动调查';
  }
}

async function reset() {
  await api('/api/reset', { method: 'POST', body: {} });
  state.incidents = [];
  state.selectedId = null;
  renderSummary({ events: 0, behaviors: 0, alerts: 0, incidents: 0, pending_approval: 0 });
  renderIncidents();
  $('#detailPanel').innerHTML = `<div class="detail-empty"><div class="radar"><span></span><i></i></div><h3>等待调查结果</h3><p>Agent 完成证据收集后，攻击图和风险结论会显示在这里。</p></div>`;
  $('#replayStatus').textContent = '等待事件输入';
  toast('演示数据已清空');
}

async function refresh() {
  const [summary, incidents] = await Promise.all([api('/api/summary'), api('/api/incidents')]);
  state.incidents = incidents;
  renderSummary(summary);
  renderIncidents();
}

function renderSummary(summary) {
  $('#metricEvents').textContent = summary.events;
  $('#metricAlerts').textContent = summary.behaviors;
  $('#metricIncidents').textContent = summary.incidents;
  $('#metricApproval').textContent = summary.pending_approval;
}

function renderIncidents() {
  $('#incidentCount').textContent = state.incidents.length;
  const list = $('#incidentList');
  if (!state.incidents.length) {
    list.innerHTML = '<div class="empty-state"><span>⌁</span><strong>暂无 Incident</strong><p>选择上方场景并启动事件回放</p></div>';
    return;
  }
  list.innerHTML = state.incidents.map((incident) => `
    <article class="incident-card ${incident.incident_id === state.selectedId ? 'active' : ''}" data-id="${esc(incident.incident_id)}">
      <div class="incident-top"><h4>${esc(incident.title)}</h4><span class="risk-pill risk-${incident.risk}">${incident.risk.toUpperCase()}</span></div>
      <p>${esc(incident.summary)}</p>
      <div class="incident-meta"><span>${esc(incident.incident_id)}</span><span>${incident.evidence_event_ids.length} EVIDENCE</span><span>${Math.round(incident.confidence * 100)}% CONF.</span></div>
    </article>`).join('');
  $$('.incident-card').forEach((card) => card.addEventListener('click', () => {
    state.selectedId = card.dataset.id;
    renderIncidents();
    renderDetail(state.incidents.find((item) => item.incident_id === state.selectedId));
  }));
}

function renderDetail(incident) {
  if (!incident) return;
  state.tab = 'story';
  $('#detailPanel').innerHTML = `
    <div class="detail-header">
      <div class="detail-title-row">
        <div><span class="risk-pill risk-${incident.risk}">${incident.risk.toUpperCase()} · ${incident.verdict.toUpperCase()}</span><h3>${esc(incident.title)}</h3></div>
        <div class="score"><strong>${incident.score}</strong><small>RISK SCORE / 100</small></div>
      </div>
      <p>${esc(incident.summary)}</p>
    </div>
    <div class="detail-tabs">
      <button class="active" data-tab="story">调查故事</button>
      <button data-tab="graph">攻击图谱</button>
      <button data-tab="actions">响应建议</button>
    </div>
    <div class="detail-content">
      <div class="tab-panel" data-panel="story">${storyPanel(incident)}</div>
      <div class="tab-panel hidden" data-panel="graph">${graphPanel(incident.graph)}</div>
      <div class="tab-panel hidden" data-panel="actions">${actionsPanel(incident)}</div>
    </div>`;
  $$('.detail-tabs button').forEach((button) => button.addEventListener('click', () => switchTab(button.dataset.tab)));
}

function switchTab(tab) {
  state.tab = tab;
  $$('.detail-tabs button').forEach((button) => button.classList.toggle('active', button.dataset.tab === tab));
  $$('.tab-panel').forEach((panel) => panel.classList.toggle('hidden', panel.dataset.panel !== tab));
}

function storyPanel(incident) {
  return `
    <section class="panel-section">
      <div class="panel-title"><h4>AGENT TOOL TRACE</h4><span>${incident.investigation_stats.tool_calls} / 6 STEPS</span></div>
      <div class="tool-trace">${incident.tool_trace.map((step) => `<div class="tool-step"><span>0${step.step}</span><strong>${esc(step.tool)}</strong><small>${esc(step.purpose)} · ${step.result_count}</small></div>`).join('')}</div>
    </section>
    <section class="panel-section root-cause">
      <div class="panel-title"><h4>ROOT CAUSE ASSESSMENT</h4><span>OBSERVED ≠ INFERRED</span></div>
      <div class="finding observed"><b>OBSERVED</b><p>${esc(incident.root_cause.observed)}</p></div>
      <div class="finding inferred"><b>INFERRED</b><p>${esc(incident.root_cause.inferred)}</p></div>
    </section>
    <section class="panel-section" id="evidence">
      <div class="panel-title"><h4>EVIDENCE-BOUND ATTACK STORY</h4><span>${incident.attack_story.length} BEHAVIOR STEPS</span></div>
      <div class="chain">${incident.attack_story.map((step) => {
        const supporting = incident.evidence.filter((item) => step.evidence.includes(item.event_id));
        return `<details class="chain-step"><summary><strong>${esc(step.behavior)}</strong><p>${esc(step.entity)}</p><code>${step.evidence.length} EVIDENCE · 点击核验</code></summary><div class="evidence-detail">${supporting.map((item) => `<div><code>${esc(item.event_id)} · ${time(item.timestamp)}</code><p>${esc(item.fact)}</p></div>`).join('')}</div></details>`;
      }).join('')}</div>
    </section>
    <section class="panel-section"><div class="panel-title"><h4>BLAST RADIUS</h4><span>${incident.blast_radius.container_count} CONTAINER</span></div><div class="finding observed"><p>${esc(incident.blast_radius.assessment)}</p></div></section>`;
}

function renderNoIncident(behaviors) {
  $('#detailPanel').innerHTML = `<div class="detail-empty"><div class="radar"><span></span><i></i></div><h3>未形成 Incident</h3><p>检测到 ${behaviors.length} 个孤立 Behavior，但没有在五分钟内满足 Web RCE 攻击 Pattern。确定性关联层已停止后续 AI 调查。</p></div>`;
}

function graphPanel(graph) {
  const positioned = positionNodes(graph.nodes);
  const byId = new Map(positioned.map((node) => [node.id, node]));
  const lines = graph.edges.map((edge) => {
    const source = byId.get(edge.source), target = byId.get(edge.target);
    if (!source || !target) return '';
    const mx = (source.x + target.x) / 2, my = (source.y + target.y) / 2;
    return `<line class="graph-edge" x1="${source.x}" y1="${source.y}" x2="${target.x}" y2="${target.y}"/><text class="graph-edge-label" x="${mx}" y="${my - 4}" text-anchor="middle">${esc(edge.relation)}</text>`;
  }).join('');
  const nodes = positioned.map((node) => `<g class="graph-node ${node.type}"><circle cx="${node.x}" cy="${node.y}" r="16"/><text x="${node.x}" y="${node.y + 28}" text-anchor="middle">${esc(truncate(node.label, 20))}</text><text x="${node.x}" y="${node.y + 3}" text-anchor="middle">${icon(node.type)}</text></g>`).join('');
  return `<section class="panel-section"><div class="panel-title"><h4>PROCESS / FILE / NETWORK GRAPH</h4><span>${graph.nodes.length} NODES · ${graph.edges.length} EDGES</span></div><div class="graph-wrap"><svg viewBox="0 0 620 310" role="img" aria-label="攻击关系图">${lines}${nodes}</svg></div></section>`;
}

function actionsPanel(incident) {
  return `<section class="panel-section" id="policy"><div class="panel-title"><h4>POLICY-GUARDED ACTIONS</h4><span>POLICY ${esc(incident.recommendations[0]?.policy.policy_version || '')}</span></div><div class="actions">${incident.recommendations.map((item) => `<div class="action"><strong>${esc(item.title)}</strong><span class="decision ${item.policy.decision}">${item.policy.decision.toUpperCase()}</span><p>${esc(item.rationale)} · ${esc(item.policy.reason)}</p></div>`).join('')}</div></section>`;
}

function positionNodes(nodes) {
  const typeOrder = ['process', 'file', 'network', 'container', 'workload'];
  const columns = new Map(typeOrder.map((type) => [type, nodes.filter((node) => node.type === type)]));
  const xByType = { process: 80, file: 255, network: 410, container: 525, workload: 590 };
  return typeOrder.flatMap((type) => {
    const group = columns.get(type);
    return group.map((node, index) => ({ ...node, x: xByType[type], y: 38 + ((index + 1) * 232 / (group.length + 1)) }));
  });
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { 'content-type': 'application/json', ...(options.headers || {}) },
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.error?.message || data.error || `HTTP ${response.status}`);
  return data;
}

function esc(value = '') { return String(value).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' }[char])); }
function time(value) { return new Intl.DateTimeFormat('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).format(new Date(value)); }
function truncate(value, length) { return value.length > length ? `${value.slice(0, length - 1)}…` : value; }
function icon(type) { return ({ process: 'P', file: 'F', network: 'N', container: 'C', workload: 'W' })[type] || '•'; }
function toast(message) { const el = $('#toast'); el.textContent = message; el.classList.add('show'); clearTimeout(toast.timer); toast.timer = setTimeout(() => el.classList.remove('show'), 2800); }

refresh().catch(() => toast('无法连接本地服务'));
