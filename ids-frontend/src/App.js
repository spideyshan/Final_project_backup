import React, { useState } from "react";
import axios from "axios";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from "recharts";

export default function App() {
  const [fsmState, setFsmState] = useState("normal");
  const [alerts, setAlerts] = useState([]);
  const [chartData, setChartData] = useState([]);

  const sendMessage = async (message) => {
    try {
      const res = await axios.post("http://127.0.0.1:5000/inspect_message", { payload: message });
      setFsmState(res.data.state);
      setAlerts((prev) => [...prev, { message, port: "-", severity: "N/A" }]);
      setChartData((prev) => [...prev, { name: message, state: res.data.state.length }]);
    } catch (error) {
      console.error("Error:", error);
      alert("Network error. Check backend.");
    }
  };

  const runNmapScan = async () => {
    try {
      const res = await axios.post("http://127.0.0.1:5000/nmap_scan", { target: "127.0.0.1", ports: "1-1024" });
      setFsmState(res.data.state);
      const newAlerts = res.data.alerts.map((a) => ({
        message: a.reasons.join(", "),
        port: a.port,
        severity: a.severity,
      }));
      setAlerts((prev) => [...prev, ...newAlerts]);
      setChartData((prev) => [...prev, { name: "Nmap Scan", state: newAlerts.length }]);
    } catch (error) {
      console.error("Error:", error);
      alert("Nmap scan failed.");
    }
  };

  return (
    <div style={{ padding: "20px", fontFamily: "Arial" }}>
      <h1 style={{ color: "#2c3e50" }}>P2P IDS Dashboard</h1>
      <h3>FSM State: {fsmState}</h3>

      <div style={{ marginBottom: "20px" }}>
        <button
          style={{ borderRadius: "12px", padding: "10px 20px", marginRight: "10px", background: "#3498db", color: "white", border: "none" }}
          onClick={() => sendMessage("hello, here is a normal message")}
        >
          Send Normal Message
        </button>

        <button
          style={{ borderRadius: "12px", padding: "10px 20px", background: "#e67e22", color: "white", border: "none" }}
          onClick={() => sendMessage("username=admin' OR '1'='1'")}
        >
          Send Suspicious Message
        </button>

        <button
          style={{ borderRadius: "12px", padding: "10px 20px", background: "#2ecc71", color: "white", border: "none", marginLeft: "10px" }}
          onClick={() => sendMessage("my password is secret123")}
        >
          Send Secret Message
        </button>

        <button
          style={{ borderRadius: "12px", padding: "10px 20px", background: "#9b59b6", color: "white", border: "none", marginLeft: "10px" }}
          onClick={runNmapScan}
        >
          Run Nmap Scan
        </button>
      </div>

      <div style={{ display: "flex", gap: "30px" }}>
        {/* Chart */}
        <div style={{ flex: 1 }}>
          <h3 style={{ color: "#34495e" }}>FSM State Chart</h3>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis />
              <Tooltip />
              <Legend />
              <Line type="monotone" dataKey="state" stroke="#8884d8" activeDot={{ r: 8 }} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        {/* Alerts Table */}
        <div style={{ flex: 1 }}>
          <h3 style={{ color: "#34495e" }}>Alerts</h3>
          <table style={{ borderCollapse: "collapse", width: "100%" }}>
            <thead>
              <tr style={{ background: "#bdc3c7" }}>
                <th style={{ padding: "8px", border: "1px solid #ccc" }}>Message</th>
                <th style={{ padding: "8px", border: "1px solid #ccc" }}>Port</th>
                <th style={{ padding: "8px", border: "1px solid #ccc" }}>Severity</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert, idx) => (
                <tr key={idx}>
                  <td style={{ padding: "8px", border: "1px solid #ccc" }}>{alert.message}</td>
                  <td style={{ padding: "8px", border: "1px solid #ccc" }}>{alert.port}</td>
                  <td style={{ padding: "8px", border: "1px solid #ccc" }}>{alert.severity}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
