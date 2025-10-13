# src/utils/persistence.py
import json, os, time
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
LOG_DIR = BASE / "logs"
PCAP_DIR = BASE / "pcaps"
LOG_DIR.mkdir(parents=True, exist_ok=True)
PCAP_DIR.mkdir(parents=True, exist_ok=True)

def save_alert_jsonl(alert: dict, fname="alerts.jsonl"):
    path = LOG_DIR / fname
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert, ensure_ascii=False) + "\n")
    return str(path)

def save_raw_bytes(data: bytes, prefix="raw"):
    ts = time.strftime("%Y-%m-%d_%H-%M-%S")
    fname = f"{prefix}_{ts}.bin"
    path = PCAP_DIR / fname
    with open(path, "wb") as f:
        f.write(data)
    return str(path)
