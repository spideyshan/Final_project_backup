# ==============================================================
# Advanced Flask Backend for P2P IDS Dashboard
# Supports: Nmap scanning, vulnerability inference, FSM state,
# live alerts, and summary charts
# ==============================================================

import os
import json
import threading
import time
import random
import nmap
from datetime import datetime, timedelta
from flask import Flask, jsonify, render_template, request

# ==============================================================
# Flask Setup
# ==============================================================
app = Flask(__name__)

# ==============================================================
# Globals / Data Stores (simulated DB)
# ==============================================================
NODES = [
    {"name": "node-A", "ip": "127.0.0.1", "status": "online", "state": "normal",
     "open_ports": 0, "vulnerabilities": [], "last_event": "none"},
    {"name": "node-B", "ip": "10.15.13.14", "status": "online", "state": "normal",
     "open_ports": 0, "vulnerabilities": [], "last_event": "none"},
    {"name": "node-C", "ip": "10.0.0.3", "status": "online", "state": "normal",
     "open_ports": 0, "vulnerabilities": [], "last_event": "none"},
    {"name": "node-D", "ip": "10.0.0.4", "status": "online", "state": "normal",
     "open_ports": 0, "vulnerabilities": [], "last_event": "none"},
]

ALERTS = []

# ==============================================================
# Nmap Setup
# ==============================================================
try:
    nm = nmap.PortScanner()
    NM_AVAILABLE = True
except Exception as e:
    print("⚠️  Nmap not available:", e)
    NM_AVAILABLE = False
    nm = None

# ==============================================================
# Vulnerability Hint Mapping
# ==============================================================
SERVICE_CVE_HINTS = {
    'http': [{'cve': 'CVE-2023-12345', 'desc': 'Outdated HTTP server version'}],
    'ssh': [{'cve': None, 'desc': 'SSH open — check version and keys'}],
    'ftp': [{'cve': None, 'desc': 'FTP open — possible anonymous login'}],
    'microsoft-ds': [{'cve': None, 'desc': 'SMB protocol — check for EternalBlue'}],
    'msrpc': [{'cve': None, 'desc': 'Microsoft RPC service — verify access controls'}],
}


def infer_vulns_from_scan(open_ports):
    """Convert open ports into vulnerability hints"""
    vulns = []
    for p in open_ports:
        svc = (p.get('service') or '').lower()
        entry = SERVICE_CVE_HINTS.get(svc.split('/')[0])
        if entry:
            for e in entry:
                vulns.append({
                    **e,
                    "port": p['port'],
                    "service": p.get('service'),
                    "version": p.get('version')
                })
        else:
            vulns.append({
                "port": p['port'],
                "service": p.get('service'),
                "version": p.get('version'),
                "cve": None,
                "desc": "No automated hint available — manual triage recommended"
            })
    return vulns


# ==============================================================
# Utility: Run Nmap Scan
# ==============================================================
def run_nmap_scan(ip, ports='1-1024'):
    """Run Nmap scan for a given IP"""
    if not NM_AVAILABLE:
        print("⚠️  Nmap not installed — returning fake results.")
        return {"ip": ip, "open": [{"port": 80, "service": "http", "version": "Apache/2.4"}]}

    try:
        scan = nm.scan(hosts=ip, ports=ports, arguments='-sV --open')
        host_info = scan['scan'].get(ip, {})
        result = {"ip": ip, "open": []}
        if host_info:
            tcp = host_info.get('tcp', {})
            for port, pdata in tcp.items():
                result['open'].append({
                    "port": port,
                    "service": pdata.get('name'),
                    "version": pdata.get('version'),
                    "extra": pdata.get('extrainfo', '')
                })
        return result
    except Exception as e:
        print("❌ Nmap scan error:", e)
        return {"ip": ip, "open": []}


# ==============================================================
# Background Scanner Thread
# ==============================================================
def do_scan_and_update_single(ip):
    """Perform scan for one IP and update node info"""
    app.logger.info(f"[SCAN_THREAD] Scanning {ip} ...")
    res = run_nmap_scan(ip)
    app.logger.info(f"[SCAN_THREAD] {ip} → {len(res.get('open', []))} open ports")

    for node in NODES:
        if node['ip'] == ip:
            node['open_ports'] = len(res.get('open', []))
            node['vulnerabilities'] = infer_vulns_from_scan(res.get('open', []))
            node['last_event'] = f"Nmap scan finished at {datetime.utcnow().isoformat()}"
            if node['vulnerabilities']:
                ALERTS.insert(0, {
                    "time": datetime.utcnow().isoformat(),
                    "node": node['name'],
                    "type": "Port Scan Result",
                    "severity": "Low",
                    "details": f"Found {len(node['vulnerabilities'])} issues"
                })
            break


def background_scanner(interval_seconds=60):
    """Continuously scan all nodes periodically"""
    app.logger.info("[BG_SCANNER] Background scanner started")
    while True:
        for node in NODES:
            try:
                do_scan_and_update_single(node['ip'])
            except Exception as e:
                app.logger.exception(f"[BG_SCANNER] Error scanning {node['ip']}: {e}")
            time.sleep(0.3)
        app.logger.info("[BG_SCANNER] Sleeping before next cycle...")
        time.sleep(interval_seconds)


def start_scanner_thread(interval_seconds=60):
    """Start the background scanning thread"""
    t = threading.Thread(target=lambda: background_scanner(interval_seconds), daemon=True)
    t.start()
    app.logger.info("[MAIN] Started background scanner thread")


# ==============================================================
# FSM (Finite State Machine) Simulation
# ==============================================================
def update_node_state(ip, new_state, event=None):
    for node in NODES:
        if node['ip'] == ip:
            node['state'] = new_state
            node['last_event'] = event or f"State changed to {new_state}"
            node['status'] = "online" if new_state == "normal" else "alert"
            if new_state in ("suspicious", "alert"):
                ALERTS.append({
                    "time": datetime.utcnow().isoformat(),
                    "node": node['name'],
                    "type": "FSM State Change",
                    "severity": "High" if new_state == "alert" else "Medium",
                    "details": node['last_event']
                })
            break


@app.route('/internal/fsm', methods=['POST'])
def internal_fsm():
    data = request.get_json()
    ip = data.get('ip')
    state = data.get('state')
    event = data.get('event')
    update_node_state(ip, state, event)
    return jsonify({"ok": True})


# ==============================================================
# Routes
# ==============================================================
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/nodes')
def api_nodes():
    return jsonify(NODES)


@app.route('/api/alerts')
def api_alerts():
    return jsonify(ALERTS)


@app.route('/api/summary')
def api_summary():
    """Generate vulnerability + attack summary for charts"""
    labels = [(datetime.utcnow() - timedelta(minutes=i)).strftime("%H:%M") for i in range(12, -1, -1)]
    attacks = [random.randint(0, 2) for _ in labels]
    vuln_counts = [len(n.get('vulnerabilities', [])) for n in NODES]
    return jsonify({
        "attacks_over_time": {"labels": labels, "counts": attacks},
        "vuln_by_node": {"nodes": [n['name'] for n in NODES], "counts": vuln_counts}
    })


# ==============================================================
# Main Nmap Scanning Endpoint
# ==============================================================
@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json(silent=True) or {}
    target = data.get('ip')

    targets = [target] if target else [n['ip'] for n in NODES]
    for ip in targets:
        do_scan_and_update_single(ip)
        time.sleep(0.3)

    return jsonify({"status": "scan completed"}), 200


# ==============================================================
# DEBUG: Direct manual scan endpoint
# ==============================================================
@app.route('/api/scan_now', methods=['POST'])
def api_scan_now():
    data = request.get_json(silent=True) or {}
    ip = data.get('ip') or '127.0.0.1'
    app.logger.info(f"[SCAN_NOW] {ip}")
    res = run_nmap_scan(ip)
    app.logger.info(f"[SCAN_NOW] Done {ip}, ports={len(res.get('open', []))}")
    return jsonify({"ok": True, "scan": res})


# ==============================================================
# Main Entry
# ==============================================================
if __name__ == '__main__':
    start_scanner_thread(interval_seconds=60)
    print("Nmap available:", NM_AVAILABLE)
    app.run(host='0.0.0.0', port=5000, debug=True)
