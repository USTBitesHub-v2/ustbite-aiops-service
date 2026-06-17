import asyncio
import json
import logging

import boto3
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from app.config import settings
from app.models import AnalyzeRequest, AnalyzeResponse, ExecuteActionRequest, ActionResult
from app.agent import run_analysis
from app.github_tools import create_remediation_pr, RemediationPRError
from app.k8s_tools import (
    list_pods,
    get_pod_logs,
    get_cluster_overview,
    restart_deployment,
    scale_deployment,
    delete_pod,
)

logging.basicConfig(level=settings.LOG_LEVEL)
logger = logging.getLogger(__name__)

app = FastAPI(title="USTBites AI Ops", version="1.0.0", docs_url="/docs")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://ustbites.com"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Auth ──────────────────────────────────────────────────────────────────────

def _require_admin(x_admin_key: str = Header(default="")):
    if settings.ADMIN_API_KEY and x_admin_key != settings.ADMIN_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid admin key")
    return x_admin_key


# ── Admin dashboard HTML (served at /) ───────────────────────────────────────

_ADMIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>USTBites Admin Ops</title>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-50 text-slate-900 min-h-screen font-sans">
<div class="max-w-7xl mx-auto p-6">
  <div class="flex items-center justify-between mb-6">
    <h1 class="text-2xl font-bold text-slate-900">USTBites <span class="text-amber-500">AI Ops</span> Console</h1>
    <div class="flex gap-2">
      <input id="apiKey" type="password" placeholder="Admin API Key" class="bg-white border border-slate-300 rounded px-3 py-1 text-sm w-56 placeholder:text-slate-400"/>
    </div>
  </div>

  <!-- Tabs -->
  <div class="flex gap-1 mb-6 border-b border-slate-200">
    <button onclick="switchTab('health')" id="tab-health" class="tab-btn px-4 py-2 text-sm rounded-t border-b-2 border-amber-500 text-slate-900 font-medium">Cluster Health</button>
    <button onclick="switchTab('logs')" id="tab-logs" class="tab-btn px-4 py-2 text-sm rounded-t border-b-2 border-transparent text-slate-400 hover:text-slate-600">Log Stream</button>
    <button onclick="switchTab('analyze')" id="tab-analyze" class="tab-btn px-4 py-2 text-sm rounded-t border-b-2 border-transparent text-slate-400 hover:text-slate-600">AI Analysis</button>
    <button onclick="switchTab('actions')" id="tab-actions" class="tab-btn px-4 py-2 text-sm rounded-t border-b-2 border-transparent text-slate-400 hover:text-slate-600">Actions</button>
  </div>

  <!-- Health Tab -->
  <div id="panel-health">
    <button onclick="loadHealth()" class="bg-slate-900 hover:bg-slate-800 text-white px-4 py-2 rounded text-sm mb-4">Refresh</button>
    <div id="health-summary" class="mb-4 text-sm text-slate-600"></div>
    <div id="pod-table" class="overflow-x-auto bg-white rounded border border-slate-200 shadow-sm">
      <table class="w-full text-sm border-collapse">
        <thead class="text-slate-500 border-b border-slate-200">
          <tr><th class="text-left py-2 px-3">Pod</th><th class="text-left py-2 px-3">Namespace</th><th class="py-2 px-3">Phase</th><th class="py-2 px-3">Ready</th><th class="py-2 px-3">Restarts</th><th class="py-2 px-3">Age</th><th class="py-2 px-3">Node</th></tr>
        </thead>
        <tbody id="pod-rows" class="divide-y divide-slate-100"></tbody>
      </table>
    </div>
  </div>

  <!-- Logs Tab -->
  <div id="panel-logs" class="hidden">
    <div class="flex gap-3 mb-4">
      <select id="log-ns" class="bg-white border border-slate-300 rounded px-3 py-1.5 text-sm">
        <option value="ustbite-backend">ustbite-backend</option>
        <option value="ustbite-frontend">ustbite-frontend</option>
        <option value="ustbite-ops">ustbite-ops</option>
        <option value="ingress-nginx">ingress-nginx</option>
        <option value="argocd">argocd</option>
      </select>
      <input id="log-pod" type="text" placeholder="pod name" class="bg-white border border-slate-300 rounded px-3 py-1.5 text-sm w-72 placeholder:text-slate-400"/>
      <button onclick="startLogStream()" class="bg-slate-900 hover:bg-slate-800 text-white px-4 py-1.5 rounded text-sm">Stream Logs</button>
      <button onclick="stopLogStream()" class="bg-slate-200 hover:bg-slate-300 text-slate-900 px-4 py-1.5 rounded text-sm">Stop</button>
    </div>
    <div id="log-box" class="bg-slate-950 rounded border border-slate-800 p-4 h-[480px] overflow-y-auto text-xs leading-5 whitespace-pre-wrap text-green-400 font-mono"></div>
  </div>

  <!-- Analyze Tab -->
  <div id="panel-analyze" class="hidden">
    <div class="mb-4">
      <label class="text-sm text-slate-500 block mb-1">Describe the problem</label>
      <textarea id="analyze-query" rows="3" placeholder="e.g. cart service is returning 503 errors, order placement is failing..." class="w-full bg-white border border-slate-300 rounded px-3 py-2 text-sm resize-none placeholder:text-slate-400"></textarea>
    </div>
    <div class="flex gap-3 mb-4">
      <input id="analyze-ns" type="text" placeholder="namespaces (comma-separated, optional)" class="bg-white border border-slate-300 rounded px-3 py-1.5 text-sm flex-1 placeholder:text-slate-400"/>
      <button onclick="runAnalysis()" class="bg-amber-500 hover:bg-amber-600 text-slate-900 px-6 py-1.5 rounded text-sm font-semibold">Run AI Analysis</button>
    </div>
    <div id="analyze-loading" class="hidden text-sm text-slate-500 animate-pulse">Investigating cluster... (may take 30-60s)</div>
    <div id="analyze-result" class="hidden space-y-4">
      <div class="bg-white rounded border border-slate-200 shadow-sm p-4">
        <div class="text-xs text-slate-400 mb-1">ROOT CAUSE</div>
        <div id="result-root-cause" class="text-sm"></div>
      </div>
      <div class="grid grid-cols-3 gap-3">
        <div class="bg-white rounded border border-slate-200 shadow-sm p-4">
          <div class="text-xs text-slate-400 mb-2">SEVERITY</div>
          <div id="result-severity" class="text-sm font-semibold"></div>
        </div>
        <div class="bg-white rounded border border-slate-200 shadow-sm p-4">
          <div class="text-xs text-slate-400 mb-2">AFFECTED SERVICES</div>
          <div id="result-services" class="text-sm"></div>
        </div>
        <div class="bg-white rounded border border-slate-200 shadow-sm p-4">
          <div class="text-xs text-slate-400 mb-2">TOOL CALLS</div>
          <div id="result-tools" class="text-sm text-slate-500"></div>
        </div>
      </div>
      <div class="bg-white rounded border border-slate-200 shadow-sm p-4">
        <div class="text-xs text-slate-400 mb-2">RECOMMENDATIONS</div>
        <ul id="result-recs" class="text-sm space-y-1 list-disc pl-4"></ul>
      </div>
    </div>
  </div>

  <!-- Actions Tab -->
  <div id="panel-actions" class="hidden">
    <p class="text-sm text-slate-500 mb-4">Proposed remediation actions from AI analysis. Review carefully before approving.</p>
    <div id="actions-list" class="space-y-3">
      <p class="text-slate-400 text-sm">Run an AI Analysis first to see proposed actions here.</p>
    </div>
  </div>
</div>

<script>
const BASE = '/api/ops';
let ws = null;
let pendingActions = [];

function key() { return document.getElementById('apiKey').value; }
function headers() { return { 'Content-Type': 'application/json', 'X-Admin-Key': key() }; }

function switchTab(name) {
  ['health','logs','analyze','actions'].forEach(t => {
    document.getElementById('panel-' + t).classList.add('hidden');
    const btn = document.getElementById('tab-' + t);
    btn.classList.remove('border-amber-500','text-slate-900','font-medium');
    btn.classList.add('border-transparent','text-slate-400');
  });
  document.getElementById('panel-' + name).classList.remove('hidden');
  const active = document.getElementById('tab-' + name);
  active.classList.add('border-amber-500','text-slate-900','font-medium');
  active.classList.remove('border-transparent','text-slate-400');
}

async function loadHealth() {
  const r = await fetch(BASE + '/pods', { headers: headers() });
  if (!r.ok) { alert('Error ' + r.status); return; }
  const pods = await r.json();
  const unhealthy = pods.filter(p => !p.ready || p.restarts > 5);
  document.getElementById('health-summary').textContent =
    `Total pods: ${pods.length}  |  Unhealthy: ${unhealthy.length}`;
  const tbody = document.getElementById('pod-rows');
  tbody.innerHTML = '';
  pods.forEach(p => {
    const ok = p.ready && p.restarts <= 5;
    const row = document.createElement('tr');
    row.className = ok ? '' : 'bg-red-50';
    row.innerHTML = `
      <td class="py-1.5 px-3 font-medium text-xs">${p.name}</td>
      <td class="py-1.5 px-3 text-slate-500 text-xs">${p.namespace}</td>
      <td class="py-1.5 px-3 text-center text-xs">${p.phase}</td>
      <td class="py-1.5 px-3 text-center">${p.ready ? '<span class="text-green-600">✓</span>' : '<span class="text-red-600">✗</span>'}</td>
      <td class="py-1.5 px-3 text-center text-xs ${p.restarts>5?'text-red-600 font-semibold':''}">${p.restarts}</td>
      <td class="py-1.5 px-3 text-center text-slate-500 text-xs">${p.age}</td>
      <td class="py-1.5 px-3 text-slate-400 text-xs truncate max-w-[160px]">${p.node}</td>`;
    tbody.appendChild(row);
  });
}

function startLogStream() {
  if (ws) ws.close();
  const ns = document.getElementById('log-ns').value;
  const pod = document.getElementById('log-pod').value.trim();
  if (!pod) { alert('Enter a pod name'); return; }
  const box = document.getElementById('log-box');
  box.textContent = `Connecting to ${pod}...\n`;
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${proto}://${location.host}/api/ops/ws/logs?namespace=${ns}&pod=${pod}&key=${key()}`);
  ws.onmessage = e => { box.textContent += e.data; box.scrollTop = box.scrollHeight; };
  ws.onerror = () => { box.textContent += '\n[WebSocket error]\n'; };
  ws.onclose = () => { box.textContent += '\n[Stream closed]\n'; };
}

function stopLogStream() { if (ws) { ws.close(); ws = null; } }

async function runAnalysis() {
  const query = document.getElementById('analyze-query').value.trim();
  if (!query) { alert('Enter a problem description'); return; }
  const nsRaw = document.getElementById('analyze-ns').value.trim();
  const namespaces = nsRaw ? nsRaw.split(',').map(s => s.trim()) : [];

  document.getElementById('analyze-loading').classList.remove('hidden');
  document.getElementById('analyze-result').classList.add('hidden');

  try {
    const r = await fetch(BASE + '/analyze', {
      method: 'POST',
      headers: headers(),
      body: JSON.stringify({ query, namespaces }),
    });
    if (!r.ok) { alert('Error ' + r.status + ': ' + await r.text()); return; }
    const data = await r.json();

    document.getElementById('result-root-cause').textContent = data.root_cause;
    const sev = data.severity || 'medium';
    const sevEl = document.getElementById('result-severity');
    sevEl.textContent = sev.toUpperCase();
    sevEl.className = 'text-sm font-semibold ' + ({critical:'text-red-600',high:'text-orange-600',medium:'text-amber-600',low:'text-green-600'}[sev]||'text-slate-500');
    document.getElementById('result-services').textContent = (data.affected_services||[]).join(', ') || 'none identified';
    document.getElementById('result-tools').textContent = (data.tool_calls_made||[]).length + ' tools called';
    const recList = document.getElementById('result-recs');
    recList.innerHTML = '';
    (data.recommendations||[]).forEach(r => {
      const li = document.createElement('li'); li.textContent = r; recList.appendChild(li);
    });

    pendingActions = data.proposed_actions || [];
    renderActions();

    document.getElementById('analyze-loading').classList.add('hidden');
    document.getElementById('analyze-result').classList.remove('hidden');
  } catch(e) {
    alert('Request failed: ' + e.message);
    document.getElementById('analyze-loading').classList.add('hidden');
  }
}

function renderActions() {
  const el = document.getElementById('actions-list');
  if (!pendingActions.length) {
    el.innerHTML = '<p class="text-slate-400 text-sm">No remediation actions proposed.</p>';
    return;
  }
  el.innerHTML = pendingActions.map((a, i) => `
    <div class="bg-white rounded border border-slate-200 shadow-sm p-4">
      <div class="flex items-start justify-between gap-4">
        <div class="flex-1">
          <div class="flex items-center gap-2 mb-1">
            <span class="text-xs bg-amber-100 text-amber-700 px-2 py-0.5 rounded font-medium">${a.action_type}</span>
            <span class="text-xs text-slate-400">${a.namespace} / ${a.target}</span>
          </div>
          <p class="text-sm text-slate-700">${a.description}</p>
        </div>
        <div class="shrink-0 flex flex-col items-end gap-1">
          <button onclick="approveAction(${i})" class="bg-red-600 hover:bg-red-700 text-white px-4 py-1.5 rounded text-sm font-semibold">
            ${a.action_type === 'create_github_pr' ? 'Approve & Open PR' : 'Approve & Execute'}
          </button>
          <a id="pr-link-${i}" href="#" target="_blank" rel="noopener" class="hidden text-xs text-blue-600 hover:text-blue-700 underline">View PR &rarr;</a>
        </div>
      </div>
    </div>`).join('');
}

async function approveAction(i) {
  const action = pendingActions[i];
  const verb = action.action_type === 'create_github_pr' ? 'Open a PR' : 'Execute';
  if (!confirm(`${verb}: ${action.action_type} on ${action.target} in ${action.namespace}?`)) return;
  const r = await fetch(BASE + '/actions/execute', {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify({ action }),
  });
  const result = await r.json();
  if (result.success && action.action_type === 'create_github_pr' && result.output) {
    const link = document.getElementById(`pr-link-${i}`);
    link.href = result.output;
    link.classList.remove('hidden');
  }
  alert(result.success ? '✓ ' + result.message : '✗ ' + (result.message || JSON.stringify(result)));
}

// Init
loadHealth();
</script>
</body>
</html>"""


# ── API endpoints ─────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def admin_dashboard():
    return HTMLResponse(content=_ADMIN_HTML)


@app.get("/health")
async def health():
    bedrock_ok = "unknown"
    try:
        bc = boto3.client("bedrock", region_name=settings.AWS_REGION)
        await asyncio.to_thread(bc.list_foundation_models)
        bedrock_ok = "reachable"
    except Exception as exc:
        bedrock_ok = f"unreachable: {exc}"
    return {"status": "ok", "bedrock": bedrock_ok, "service": "aiops-service"}


@app.get("/pods")
async def pods_status(_: str = Depends(_require_admin)):
    return await list_pods("all")


@app.get("/pods/{namespace}/{pod_name}/logs")
async def pod_logs(namespace: str, pod_name: str, lines: int = 150, _: str = Depends(_require_admin)):
    return {"logs": await get_pod_logs(namespace, pod_name, lines)}


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(body: AnalyzeRequest, _: str = Depends(_require_admin)):
    logger.info("Analysis requested: %s", body.query)
    return await run_analysis(body.query, body.namespaces)


@app.post("/actions/execute", response_model=ActionResult)
async def execute_action(body: ExecuteActionRequest, _: str = Depends(_require_admin)):
    action = body.action
    logger.info("Executing action: %s on %s/%s", action.action_type, action.namespace, action.target)

    if action.action_type == "restart_deployment":
        result = await restart_deployment(action.namespace, action.target)
        return ActionResult(
            success=result.get("success", False),
            message=result.get("message", result.get("error", "Unknown result")),
        )
    elif action.action_type == "scale_deployment":
        replicas = action.params.get("replicas", 1)
        result = await scale_deployment(action.namespace, action.target, replicas)
        return ActionResult(
            success=result.get("success", False),
            message=result.get("message", result.get("error", "Unknown result")),
        )
    elif action.action_type == "delete_pod":
        result = await delete_pod(action.namespace, action.target)
        return ActionResult(
            success=result.get("success", False),
            message=result.get("message", result.get("error", "Unknown result")),
        )
    elif action.action_type == "create_github_pr":
        try:
            pr = await create_remediation_pr(
                file_path=action.target,
                key_path=action.params.get("key_path", ""),
                new_value=action.params.get("new_value"),
                description=action.description,
                pr_title=action.params.get("pr_title"),
                pr_description=action.params.get("pr_description"),
            )
            return ActionResult(
                success=True,
                message=f"Opened PR #{pr['pr_number']}",
                output=pr["pr_url"],
            )
        except RemediationPRError as exc:
            return ActionResult(success=False, message=str(exc))
    else:
        return ActionResult(success=False, message=f"Unknown action type: {action.action_type}")


# ── WebSocket: live log streaming ─────────────────────────────────────────────

@app.websocket("/ws/logs")
async def ws_logs(websocket: WebSocket, namespace: str, pod: str, key: str = ""):
    if settings.ADMIN_API_KEY and key != settings.ADMIN_API_KEY:
        await websocket.close(code=4001)
        return

    await websocket.accept()
    logger.info("WS log stream opened: %s/%s", namespace, pod)
    last_lines = 0

    try:
        while True:
            raw = await get_pod_logs(namespace, pod, tail_lines=200)
            lines = raw.splitlines()
            if len(lines) > last_lines:
                new_lines = lines[last_lines:]
                await websocket.send_text("\n".join(new_lines) + "\n")
                last_lines = len(lines)
            await asyncio.sleep(4)
    except WebSocketDisconnect:
        logger.info("WS log stream closed: %s/%s", namespace, pod)
    except Exception as exc:
        logger.error("WS error: %s", exc)
        try:
            await websocket.send_text(f"\n[Stream error: {exc}]\n")
        except Exception:
            pass
