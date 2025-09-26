# src/run_demo.py
"""
Demo that runs the original P2P message tests AND triggers an Nmap scan using the integrated detector.
"""

import time
from p2p.manager import create_two_nodes
from ids.detector import IntegratedDetector

def main():
    # create and start nodes
    n1, n2 = create_two_nodes()

    # integrated detector attached to node2
    detector = IntegratedDetector(node_name="node2")

    # monkeypatch n2's handler to feed messages into detector
    def custom_handle(client, addr):
        data = b''
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            data += chunk
        import json
        try:
            msg = json.loads(data.decode())
            print("[node2] Received parsed:", msg)
            # feed to integrated detector (message-inspection)
            detector.inspect_message(data, parsed_msg=str(msg))
        except Exception as e:
            print("[node2] Received raw:", data)
            detector.inspect_message(data)
        client.close()

    # replace internal handler
    n2._handle_client = custom_handle

    time.sleep(1)
    # normal message
    n1.send('127.0.0.1', 9102, {"type":"data","payload":"hello, here is a normal message"})
    time.sleep(0.5)
    # SQLi payload
    n1.send('127.0.0.1', 9102, {"type":"login","payload":"username=admin' OR '1'='1'"})
    time.sleep(0.5)
    # secret leak
    n1.send('127.0.0.1', 9102, {"type":"data","payload":"my password is secret123"})
    time.sleep(1)

    # Now run an Nmap scan *against the host of node2* (local test)
    target = "127.0.0.1"   # ensure you have permission to scan
    print("Running integrated Nmap scan against", target)
    alerts = detector.run_nmap_scan(target, ports="1-1024")  # choose port range
    print(f"Nmap scan finished — {len(alerts)} alert(s) generated.")
    for a in alerts:
        print(a)

    print("Final FSM state:", detector.current_state())

    # cleanup
    n1.stop()
    n2.stop()

if __name__ == "__main__":
    main()
