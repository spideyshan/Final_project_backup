from flask import Flask, request, jsonify
from flask_cors import CORS

from ids.detector import IntegratedDetector

app = Flask(__name__)
CORS(app)  # enable frontend <-> backend communication

# create one detector instance
detector = IntegratedDetector(node_name="node2")

@app.route("/")
def home():
    return jsonify({"message": "Backend is running!"})

@app.route("/inspect_message", methods=["POST"])
def inspect_message():
    data = request.get_json()
    payload = data.get("payload", "")
    detector.inspect_message(payload.encode(), parsed_msg=payload)
    return jsonify({"state": detector.current_state()})

@app.route("/nmap_scan", methods=["POST"])
def nmap_scan():
    data = request.get_json()
    target = data.get("target", "127.0.0.1")
    ports = data.get("ports", "1-1024")
    alerts = detector.run_nmap_scan(target, ports=ports)
    return jsonify({"state": detector.current_state(), "alerts": alerts})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
