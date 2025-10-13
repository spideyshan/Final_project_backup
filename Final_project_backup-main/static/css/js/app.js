// static/js/app.js
// Corrected frontend script for the dashboard
// Must match HTML element IDs: 'btn-scan' and 'btn-refresh'

console.log("app.js loaded");

const API_BASE = '/api';

// helper for pretty time
function fmtTime(ts) {
  if (!ts) return '—';
  try { return new Date(ts).toLocaleString(); } catch(e) { return ts; }
}

// render functions (minimal so you can see updates)
function renderNodes(nodes) {
  const container = document.getElementById('nodes-container');
  if (!container) return;
  container.innerHTML = '';
  if (!nodes || nodes.length === 0) {
    container.innerHTML = '<div class="text-muted">No nodes</div>';
    return;
  }
  nodes.forEach(n => {
    const el = document.createElement('div');
    el.className = 'node-card';
    el.innerHTML = `
      <div>
        <strong>${n.name}</strong><br/><small class="text-muted">${n.ip}</small>
      </div>
      <div style="text-align:right">
        <div class="node-badge ${n.status === 'online' ? 'node-online' : n.status === 'suspicious' ? 'node-warning' : 'node-offline'}">
          ${n.status ? n.status.toUpperCase() : '—'}
        </div>
        <div style="font-size:11px;margin-top:4px">${n.open_ports || 0} ports</div>
      </div>
    `;
    container.appendChild(el);
  });
}

function renderAlerts(alerts) {
  const tbody = document.querySelector('#alerts-table tbody');
  if (!tbody) return;
  tbody.innerHTML = '';
  if (!alerts || alerts.length === 0) {
    tbody.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No alerts</td></tr>`;
    return;
  }
  alerts.forEach(a => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${fmtTime(a.time)}</td><td>${a.node}</td><td>${a.type}</td><td>${a.severity}</td>`;
    tr.onclick = () => { document.getElementById('alert-detail').textContent = JSON.stringify(a, null, 2); };
    tbody.appendChild(tr);
  });
}

async function refreshAllOnce() {
  try {
    const [nodesRes, alertsRes, summaryRes] = await Promise.all([
      fetch(`${API_BASE}/nodes`),
      fetch(`${API_BASE}/alerts`),
      fetch(`${API_BASE}/summary`)
    ]);
    if (!nodesRes.ok || !alertsRes.ok || !summaryRes.ok) {
      console.error('One or more API calls failed', nodesRes, alertsRes, summaryRes);
      return;
    }
    const nodes = await nodesRes.json();
    const alerts = await alertsRes.json();
    const summary = await summaryRes.json();
    console.log('refreshed data', { nodes, alerts, summary });
    renderNodes(nodes);
    renderAlerts(alerts);
    // (charts omitted for brevity — they can be updated here)
  } catch (err) {
    console.error('refreshAllOnce error', err);
  }
}

document.addEventListener('DOMContentLoaded', () => {
  console.log('DOM ready, hooking buttons');

  // match HTML buttons
  const runScanBtn = document.getElementById('btn-scan');
  const refreshBtn = document.getElementById('btn-refresh');

  if (!runScanBtn) console.warn('Run scan button not found (#btn-scan)');
  if (!refreshBtn) console.warn('Refresh button not found (#btn-refresh)');

  // click handler for scan
  if (runScanBtn) {
    runScanBtn.addEventListener('click', async (e) => {
      e.preventDefault();
      console.log('Run Nmap Scan clicked');
      runScanBtn.disabled = true;
      runScanBtn.textContent = 'Scanning…';
      try {
        const res = await fetch(`${API_BASE}/scan`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip: '127.0.0.1' }) // tests local host; server will scan configured nodes if null
        });
        const data = await res.json().catch(()=>({}));
        console.log('scan response', res.status, data);
        alert('Scan started: ' + (data.status || res.status));
        // refresh data after small delay so UI shows results
        setTimeout(refreshAllOnce, 1500);
      } catch (err) {
        console.error('Scan request failed', err);
        alert('Failed to start scan. See console.');
      } finally {
        runScanBtn.disabled = false;
        runScanBtn.textContent = 'Run Nmap Scan';
      }
    });
  }

  if (refreshBtn) refreshBtn.addEventListener('click', refreshAllOnce);

  // initial load
  refreshAllOnce();
});
