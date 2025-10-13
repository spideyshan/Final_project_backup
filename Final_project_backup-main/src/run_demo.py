# src/run_demo.py
import time, json
from p2p.manager import create_two_nodes
from ids.detector import SimpleIDS

def main():
    n1, n2 = create_two_nodes()
    ids = SimpleIDS(node_name="node2")

    def custom_handle(client, addr):
        data = b''
        while True:
            chunk = client.recv(4096)
            if not chunk:
                break
            data += chunk
        try:
            msg = json.loads(data.decode())
            print("[node2] Received parsed:", msg)
            ids.inspect_message(data, parsed_msg=str(msg))
        except Exception:
            print("[node2] Received raw:", data)
            ids.inspect_message(data)
        client.close()

    n2._handle_client = custom_handle

    time.sleep(1)
    n1.send('127.0.0.1', 9102, {"type":"data","payload":"hello, here is a normal message"})
    time.sleep(0.5)
    n1.send('127.0.0.1', 9102, {"type":"login","payload":"username=admin' OR '1'='1'"})
    time.sleep(0.5)
    n1.send('127.0.0.1', 9102, {"type":"data","payload":"my password is secret123"})
    time.sleep(1)
    n1.stop(); n2.stop()
    print("Demo finished. Check logs/ and pcaps/")

if __name__ == "__main__":
    main()
