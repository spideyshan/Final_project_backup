# src/detection.py

class SimpleIDS:
    def __init__(self):
        # dictionary to keep track of connections
        # format: {"ip": {port1, port2, port3}}
        self.connections = {}

    def detect(self, ip, port):
        """
        Detects if an IP is scanning multiple ports.
        """
        if ip not in self.connections:
            self.connections[ip] = set()

        # add this port to the list of ports seen for this IP
        self.connections[ip].add(port)

        # rule: if same IP connects to 5+ different ports, flag as scan
        if len(self.connections[ip]) >= 5:
            return f"[ALERT] Possible port scan detected from {ip}"

        return None

