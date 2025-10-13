# src/p2p/node.py
import socket
import threading
import json

class P2PNode:
    def __init__(self, host, port, peers=None, node_name=None):
        self.host = host
        self.port = port
        self.peers = peers or []
        self.node_name = node_name or f"{host}:{port}"
        self.server = None
        self.running = False

    def start_server(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.host, self.port))
        self.server.listen(5)
        self.running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()
        print(f"[{self.node_name}] Listening on {self.host}:{self.port}")

    def _accept_loop(self):
        while self.running:
            try:
                client, addr = self.server.accept()
                threading.Thread(target=self._handle_client, args=(client, addr), daemon=True).start()
            except Exception as e:
                print(f"[{self.node_name}] Accept error: {e}")

    def _handle_client(self, client, addr):
        data = b''
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            data += chunk
        try:
            msg = json.loads(data.decode())
            print(f"[{self.node_name}] Received from {addr}: {msg}")
        except Exception:
            print(f"[{self.node_name}] Received raw: {data}")
        client.close()

    def send(self, host, port, payload: dict):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, port))
            s.sendall(json.dumps(payload).encode())
            s.close()
            print(f"[{self.node_name}] Sent to {host}:{port} -> {payload}")
        except Exception as e:
            print(f"[{self.node_name}] Send error: {e}")

    def stop(self):
        self.running = False
        try:
            if self.server:
                self.server.close()
        except:
            pass
