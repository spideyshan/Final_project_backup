# src/ids/detector.py
"""
Integrated detector module:
- SimpleIDS: original message-signature FSM-based detector
- NmapDetector: runs nmap scans, generates alerts and recommendations
Both detectors feed into the same FSM. Nmap high-severity findings escalate FSM state.
"""

import re
import time
import json
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

# persistence & logger (use your existing utils)
from utils.persistence import save_alert_jsonl, save_raw_bytes
from utils.logger import get_logger

logger = get_logger()

# Try python-nmap
HAS_PYTHON_NMAP = False
try:
    import nmap
    HAS_PYTHON_NMAP = True
except Exception:
    HAS_PYTHON_NMAP = False

# ---------------------------
# FSM Model (light wrapper)
# ---------------------------
from ids.fsm_ids import IDSModel

class FSMController:
    def __init__(self, node_name="node"):
        self.model = IDSModel()
        self.node = node_name

    def advance_due_to_message(self):
        # used by SimpleIDS when signatures seen
        if self.model.state == 'normal':
            self.model.saw_suspicious()
        elif self.model.state == 'suspicious':
            self.model.escalate()
        elif self.model.state == 'confirmed':
            self.model.alert()

    def advance_due_to_nmap_severity(self, severity):
        # severity: 'low'|'medium'|'high'
        # escalate more aggressively for high severity
        if severity == "high":
            # escalate twice to go to alert quicker
            if self.model.state == 'normal':
                self.model.saw_suspicious()
                self.model.escalate()
            elif self.model.state == 'suspicious':
                self.model.escalate()
                self.model.alert()
            elif self.model.state == 'confirmed':
                self.model.alert()
        elif severity == "medium":
            # medium -> suspicious/confirmed
            if self.model.state == 'normal':
                self.model.saw_suspicious()
            elif self.model.state == 'suspicious':
                self.model.escalate()
            elif self.model.state == 'confirmed':
                self.model.alert()
        else:
            # low severity: only mark suspicious if normal
            if self.model.state == 'normal':
                self.model.saw_suspicious()

    def current_state(self):
        return self.model.state

# ---------------------------
# Simple message-based IDS
# ---------------------------

class SimpleIDS:
    def __init__(self, fsm_controller: FSMController, node_name="node", logger=None):
        self.fsm = fsm_controller
        self.node = node_name
        self.logger = logger or get_logger()
        # signatures to detect in payloads/messages
        self.signatures = {
            "sql_injection": re.compile(r"(or\s+1=1|'1'='1'|--)", re.IGNORECASE),
            "sensitive_keyword": re.compile(r"(password|secret|login|passwd)", re.IGNORECASE)
        }

    def inspect_message(self, raw_bytes: bytes, parsed_msg=None):
        s = parsed_msg if parsed_msg is not None else raw_bytes.decode(errors='ignore')
        ts = time.time()
        if self.signatures["sql_injection"].search(s):
            self.logger.info(f"[IDS] SQL injection pattern detected on {self.node}")
            alert = {
                "timestamp": ts,
                "node": self.node,
                "type": "message_sql_injection",
                "severity": "high",
                "evidence": s[:300],
            }
            save_alert_jsonl(alert)
            # advance FSM
            self.fsm.advance_due_to_message()
        elif self.signatures["sensitive_keyword"].search(s):
            self.logger.info(f"[IDS] Sensitive keyword detected on {self.node}")
            alert = {
                "timestamp": ts,
                "node": self.node,
                "type": "message_sensitive_keyword",
                "severity": "medium",
                "evidence": s[:300],
            }
            save_alert_jsonl(alert)
            self.fsm.advance_due_to_message()
        else:
            # reset for demo (optional)
            # self.fsm.model.reset()  # uncomment if you want auto reset
            self.logger.info(f"[IDS] Normal traffic on {self.node}. FSM state: {self.fsm.current_state()}")

# ---------------------------
# Nmap-based detector
# ---------------------------

class NmapDetector:
    """
    Integrated Nmap detector. Runs nmap (python-nmap preferred, otherwise CLI fallback),
    analyzes open ports/services/scripts and writes alerts. Also uses FSMController to escalate state.
    """

    def __init__(self, fsm_controller: FSMController, scan_args="-sV --script=vuln", logger=None):
        self.fsm = fsm_controller
        self.scan_args = scan_args
        self.logger = logger or get_logger()

    def _recommend_mitigation(self, port, service, product, version):
        service = (service or "").lower()
        product = (product or "").lower()
        recs = []
        if "telnet" in service or "telnet" in product:
            recs.append("Disable Telnet; use SSH and firewall rules to restrict access.")
        if "ftp" in service or "ftp" in product:
            recs.append("Disable anonymous FTP; use SFTP or FTPS and strong authentication.")
        if "ssh" in service:
            recs.append("Enforce key-based auth, disable password auth, keep OpenSSH updated.")
        if "http" in service or "nginx" in product or "apache" in product:
            recs.append("Patch web server and web apps; run web vulnerability scanner (OWASP ZAP).")
        if "mysql" in service or "mysql" in product:
            recs.append("Bind DB to localhost, require strong credentials, restrict remote access.")
        if not recs:
            recs.append("Investigate service, patch to latest version, restrict access with firewall.")
        return recs

    def scan(self, target, ports=None, timeout=300):
        """
        Run nmap scan on target. ports can be None or string like '1-1024'.
        Returns list of alerts (dicts) and writes them to persistence.
        """
        self.logger.info(f"[NmapDetector] Starting scan on {target} (ports={ports})")
        ts = time.time()
        findings = []

        # Preferred python-nmap
        if HAS_PYTHON_NMAP:
            try:
                nm = nmap.PortScanner()
                if ports:
                    nm.scan(target, ports=str(ports), arguments=self.scan_args)
                else:
                    nm.scan(target, arguments=self.scan_args)
                hosts = nm.all_hosts()
                if not hosts:
                    self.logger.warning(f"[NmapDetector] No hosts found in python-nmap scan for {target}")
                for host in hosts:
                    if 'tcp' in nm[host]:
                        for portnum, pdata in nm[host]['tcp'].items():
                            port_info = {
                                "port": portnum,
                                "state": pdata.get("state"),
                                "service": pdata.get("name"),
                                "product": pdata.get("product"),
                                "version": pdata.get("version"),
                                "extrainfo": pdata.get("extrainfo"),
                                "scripts": pdata.get("script", {})
                            }
                            findings.append(port_info)
            except Exception as e:
                self.logger.error(f"[NmapDetector] python-nmap failed: {e}")
                return self._scan_subprocess_xml(target, ports)
        else:
            return self._scan_subprocess_xml(target, ports)

        alerts = self._analyze_findings(target, findings, ts)
        return alerts

    def _scan_subprocess_xml(self, target, ports=None):
        if not shutil.which("nmap"):
            self.logger.error("nmap CLI not found in PATH. Install it (brew install nmap on macOS).")
            raise FileNotFoundError("nmap not installed")

        cmd = ["nmap", "-oX", "-", "-sV", "--script=vuln"]
        if ports:
            cmd += ["-p", str(ports)]
        cmd.append(target)
        self.logger.info(f"[NmapDetector] Running: {' '.join(cmd)}")
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if p.returncode != 0:
            self.logger.error(f"[NmapDetector] nmap failed: {p.stderr}")
            raise RuntimeError("nmap CLI failed")
        xml_out = p.stdout.encode()
        # save raw XML for audit
        try:
            save_raw_bytes(xml_out, prefix="nmap_xml")
        except Exception:
            pass

        root = ET.fromstring(xml_out)
        findings = []
        for host in root.findall("host"):
            addr = host.find("address")
            ip = addr.get("addr") if addr is not None else target
            ports_node = host.find("ports")
            if ports_node is None:
                continue
            for port in ports_node.findall("port"):
                portnum = int(port.get("portid"))
                state = port.find("state").get("state")
                service_node = port.find("service")
                service_name = service_node.get("name") if service_node is not None else None
                product = service_node.get("product") if service_node is not None else None
                version = service_node.get("version") if service_node is not None else None
                portinfo = {
                    "port": portnum,
                    "state": state,
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "scripts": {}
                }
                for script in port.findall("script"):
                    name = script.get("id")
                    out = script.get("output")
                    portinfo["scripts"][name] = out
                findings.append(portinfo)
        ts = time.time()
        alerts = self._analyze_findings(target, findings, ts)
        return alerts

    def _analyze_findings(self, target, findings, timestamp):
        alerts = []
        for f in findings:
            if f.get("state") != "open":
                continue
            port = f.get("port")
            service = f.get("service")
            product = f.get("product")
            version = f.get("version")
            scripts = f.get("scripts", {})

            severity = "low"
            reasons = []
            # heuristics
            if port in (21, 23, 69):
                severity = "high"
                reasons.append("Insecure service (cleartext protocol).")
            if 0 < port < 1024 and port not in (22, 80, 443):
                if severity != "high":
                    severity = "medium"
                reasons.append("Well-known low port open; verify necessity.")
            if scripts:
                severity = "high"
                for k, v in scripts.items():
                    reasons.append(f"{k}: {v}")
            if version and any(tok in str(version).lower() for tok in ["0.9", "1.0", "outdated", "deprecated"]):
                severity = "high"
                reasons.append("Version string suggests outdated software.")

            alert = {
                "timestamp": timestamp,
                "target": target,
                "port": port,
                "service": service,
                "product": product,
                "version": version,
                "scripts": scripts,
                "severity": severity,
                "reasons": reasons or ["Open service detected"],
                "recommendations": self._recommend_mitigation(port, service, product, version)
            }
            alerts.append(alert)
            # persist
            try:
                save_alert_jsonl(alert)
            except Exception as e:
                self.logger.error(f"Failed to save alert: {e}")

            self.logger.info(f"[NmapDetector] Alert: {target}:{port} {service} severity={severity}")
            # escalate FSM depending on severity
            try:
                self.fsm.advance_due_to_nmap_severity(severity)
            except Exception as e:
                self.logger.error(f"FSM escalation failed: {e}")

        return alerts

# ---------------------------
# Convenience wrapper: Integrated Detector Manager
# ---------------------------

class IntegratedDetector:
    """
    Holds FSM controller, message IDS, and nmap detector in one place.
    Use this in your run_demo.py.
    """
    def __init__(self, node_name="node"):
        self.fsm = FSMController(node_name=node_name)
        self.msg_ids = SimpleIDS(self.fsm, node_name=node_name)
        self.nmap = NmapDetector(self.fsm)

    def inspect_message(self, raw_bytes, parsed_msg=None):
        self.msg_ids.inspect_message(raw_bytes, parsed_msg)

    def run_nmap_scan(self, target, ports=None):
        return self.nmap.scan(target, ports=ports)

    def current_state(self):
        return self.fsm.current_state()
