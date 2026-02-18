// static/js/app.js (advanced frontend)
// Fetch + render nodes, alerts, summary; charts + modal + toasts + FSM selection

console.log("Advanced app.js loaded");
const API_BASE = '/api';
let vulnChart = null, attackChart = null;
let selectedNodeIp = null;

// small helper: show a bootstrap toast
function showToast(title, message, timeout=2500) {
  const wrap = document.getElementById('toast-wrap');
  const id = 't' + Math.random().toString(36).slice(2,9);
  wrap.insertAdjacentHTML('beforeend', `
    <div id="${id}" class="toast align-items-center text-bg-dark border-0 mb-2" role="alert" aria-live="assertive" aria-atomic="true">
      <div class="d-flex">
        <div class="toast-body">
          <strong>${title}</strong><div>${message}</div>
        </div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
      </div>
    </div>
  `);
  const el = document.getElementById(id);
  const toast = new bootstrap.Toast(el, { delay: timeout });
  toast.show();
  el.addEventListener('hidden.bs.toast', ()=> el.remove());
}

// format time prettily
function fmtTime(ts) {
  if (!ts) return '—';
  try { return new Date(ts).toLocaleString(); } catch(e) { return ts; }
}

/* -------------------------
   Rendering nodes & selection
   ------------------------- */
function renderNodes(nodes) {
  const container = document.getElementById('nodes-container');
  container.innerHTML = '';
  if (!nodes || !nodes.length) {
    container.innerHTML = '<div class="text-muted p-3">No nodes</div>';
    return;
  }
  // search filter
  const q = document.getElementById('node-search').value.trim().toLowerCase();
  const filtered = q ? nodes.filter(n => (n.name + ' ' + n.ip).toLowerCase().includes(q)) : nodes;

  filtered.forEach(n => {
    const statusClass = n.status === 'online' ? 'badge-online' : n.status === 'suspicious' ? 'badge-suspicious' : 'badge-alert';
    const el = document.createElement('div');
    el.className = 'node-card';
    el.innerHTML = `
      <div>
        <div style="display:flex; gap:10px; align-items:center">
          <div style="width:8px; height:8px; border-radius:50%; background:${n.status==='online'?'#198754':n.status==='suspicious'?'#ffc107':'#dc3545'}"></div>
          <strong>${n.name}</strong>
        </div>
        <div class="text-muted small">${n.ip}</div>
      </div>
      <div style="text-align:right">
        <div class="small text-muted">${n.open_ports || 0} ports</div>
      </div>
    `;
    el.style.cursor = 'pointer';
    el.onclick = () => {
      selectedNodeIp = n.ip;
      renderFSMFromNodes(nodes);
      highlightNodeVulns(n.ip);
    };
    container.appendChild(el);
  });

  renderNodeVulnsList(nodes);
  renderFSMFromNodes(nodes);
}

/* -------------------------
   Node vulnerabilities list
   ------------------------- */
function renderNodeVulnsList(nodes) {
  const nv = document.getElementById('node-vulns');
  nv.innerHTML = '';
  nodes.forEach(n => {
    const div = document.createElement('div');
    div.dataset.ip = n.ip;
    div.style.padding = '8px 4px';
    const vulns = n.vulnerabilities || [];
    let inner = `<div class="d-flex justify-content-between align-items-center"><strong>${n.name}</strong><small class="text-muted">${vulns.length} findings</small></div>`;
    if (vulns.length) {
      inner += '<ul class="mb-2">';
      vulns.forEach(v => {
        const ver = v.version ? ` ${v.version}` : '';
        const desc = v.desc ? ` — ${v.desc}` : '';
        inner += `<li><small>${v.port} ${v.service||''}${ver}${desc}</small></li>`;
      });
      inner += '</ul>';
    } else {
      inner += '<div class="text-muted small">No findings</div>';
    }
    div.innerHTML = inner;
    nv.appendChild(div);
  });
  highlightNodeVulns(selectedNodeIp);
}

function highlightNodeVulns(ip) {
  const nv = document.getElementById('node-vulns');
  if (!nv) return;
  Array.from(nv.children).forEach(c => { c.style.background = (c.dataset.ip === ip) ? '#f5f9fb' : ''; });
}

/* -------------------------
   FSM display
   ------------------------- */
function renderFSMFromNodes(nodes) {
  const node = nodes.find(n => n.ip === selectedNodeIp) || (nodes.length ? nodes[0] : null);
  document.getElementById('fsm-current-node').textContent = node ? `${node.name} (${node.ip})` : '—';
  document.getElementById('fsm-current-state').textContent = node ? (node.state || '—') : '—';
  document.getElementById('fsm-last-event').textContent = node ? (node.last_event || '—') : '—';
}

/* -------------------------
   Alerts rendering + modal
   ------------------------- */
function renderAlerts(alerts) {
  const tbody = document.querySelector('#alerts-table tbody');
  tbody.innerHTML = '';
  if (!alerts || !alerts.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No alerts</td></tr>';
    return;
  }
  alerts.forEach(a => {
    const tr = document.createElement('tr');
    tr.style.cursor = 'pointer';
    tr.innerHTML = `<td>${fmtTime(a.time)}</td><td>${a.node}</td><td>${a.type}</td><td>${a.severity}</td>`;
    tr.onclick = () => {
      document.getElementById('alert-modal-body').textContent = JSON.stringify(a, null, 2);
      const modal = new bootstrap.Modal(document.getElementById('alertModal'));
      modal.show();
      document.getElementById('alert-detail').textContent = JSON.stringify(a, null, 2);
    };
    tbody.appendChild(tr);
  });
}

/* -------------------------
   Summary charts renderer
   ------------------------- */
function renderSummary(summary) {
  if (!summary) return;
  const vnodes = summary.vuln_by_node.nodes || [];
  const vcounts = summary.vuln_by_node.counts || [];
  const vctx = document.getElementById('vulnChart');
  if (vctx) {
    if (vulnChart) vulnChart.destroy();
    vulnChart = new Chart(vctx, {
      type: 'bar',
      data: { labels: vnodes, datasets: [{ label: 'Vulnerabilities', data: vcounts, backgroundColor: 'rgba(54,162,235,0.7)' }] },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
    });
  }

  const alabels = summary.attacks_over_time.labels || [];
  const acounts = summary.attacks_over_time.counts || [];
  const actx = document.getElementById('attackChart');
  if (actx) {
    if (attackChart) attackChart.destroy();
    attackChart = new Chart(actx, {
      type: 'line',
      data: { labels: alabels, datasets: [{ label: 'Attacks', data: acounts, borderColor: '#0d6efd', tension: 0.2, pointRadius: 3 }] },
      options: { responsive: true, maintainAspectRatio: false, scales: { y: { beginAtZero: true } } }
    });
  }
}

/* -------------------------
   Fetch everything
   ------------------------- */
async function refreshAllOnce() {
  try {
    const [nodesRes, alertsRes, summaryRes] = await Promise.all([
      fetch(`${API_BASE}/nodes`),
      fetch(`${API_BASE}/alerts`),
      fetch(`${API_BASE}/summary`)
    ]);
    if (!nodesRes.ok || !alertsRes.ok || !summaryRes.ok) {
      console.error('API failed', nodesRes, alertsRes, summaryRes);
      return;
    }
    const nodes = await nodesRes.json();
    const alerts = await alertsRes.json();
    const summary = await summaryRes.json();

    renderNodes(nodes);
    renderAlerts(alerts);
    renderSummary(summary);
  } catch (err) {
    console.error('refreshAllOnce error', err);
  }
}

/* -------------------------
   Hook UI events
   ------------------------- */
document.addEventListener('DOMContentLoaded', () => {
  const scanBtn = document.getElementById('btn-scan');
  const refreshBtn = document.getElementById('btn-refresh');
  const search = document.getElementById('node-search');

  scanBtn.addEventListener('click', async () => {
    scanBtn.disabled = true;
    scanBtn.innerHTML = '<i class="bi bi-hourglass-split"></i> Scanning…';
    showToast('Scan', 'Nmap scan started');
    try {
      await fetch(`${API_BASE}/scan`, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ ip: '127.0.0.1' }) });
      // refresh after a short delay to let background scan update data
      setTimeout(() => {
        refreshAllOnce();
        showToast('Scan', 'Scan completed (or in progress — UI refreshed)');
      }, 1500);
    } catch (e) {
      console.error(e);
      showToast('Scan', 'Failed to start scan');
    } finally {
      scanBtn.disabled = false;
      scanBtn.innerHTML = '<i class="bi bi-search"></i> Run Nmap Scan';
    }
  });

  refreshBtn.addEventListener('click', refreshAllOnce);
  search.addEventListener('input', refreshAllOnce);

  // initial load + poll
  refreshAllOnce();
  setInterval(refreshAllOnce, 5000);
});
