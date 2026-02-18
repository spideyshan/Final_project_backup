# src/ids/detector.py
import re, time
from ids.fsm_ids import IDSModel
from utils.logger import get_logger
from utils.persistence import save_alert_jsonl, save_raw_bytes

_logger = get_logger()

class SimpleIDS:
    def __init__(self, node_name="node"):
        self.model = IDSModel()
        self.node = node_name
        self.signatures = {
            "sql_injection": re.compile(r"(or\s+1=1|'1'='1'|--)", re.IGNORECASE),
            "sensitive_keyword": re.compile(r"(password|secret|login)", re.IGNORECASE)
        }

    def inspect_message(self, raw_bytes: bytes, parsed_msg=None):
        s = parsed_msg if parsed_msg is not None else raw_bytes.decode(errors='ignore')
        ts = time.time()
        if self.signatures["sql_injection"].search(s):
            _logger.info(f"[IDS] SQL injection pattern detected on {self.node}")
            self._record_alert("sql_injection", "high", s, ts, raw_bytes)
            self._advance_fsm()
        elif self.signatures["sensitive_keyword"].search(s):
            _logger.info(f"[IDS] Sensitive keyword detected on {self.node}")
            self._record_alert("sensitive_keyword", "medium", s, ts, raw_bytes)
            self._advance_fsm()
        else:
            if self.model.state != 'normal':
                self.model.reset()
            _logger.info(f"[IDS] Normal traffic on {self.node}")

    def _advance_fsm(self):
        if self.model.state == 'normal':
            self.model.saw_suspicious()
        elif self.model.state == 'suspicious':
            self.model.escalate()
        elif self.model.state == 'confirmed':
            self.model.alert()

    def _record_alert(self, alert_type, severity, evidence, ts, raw_bytes):
        alert = {
            "timestamp": ts,
            "node": self.node,
            "alert_type": alert_type,
            "severity": severity,
            "evidence": evidence[:300],
            "fsm_state": self.model.state
        }
        save_alert_jsonl(alert)
        try:
            path = save_raw_bytes(raw_bytes, prefix=alert_type)
            _logger.info(f"[IDS] Saved raw payload to {path}")
        except Exception as e:
            _logger.error(f"[IDS] Failed to save raw bytes: {e}")
