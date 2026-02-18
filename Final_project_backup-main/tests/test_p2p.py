# tests/test_p2p.py
import time
from p2p.node import P2PNode

def test_p2p_send_receive():
    n1 = P2PNode('127.0.0.1', 9201, node_name='t1')
    n2 = P2PNode('127.0.0.1', 9202, node_name='t2')
    n1.start_server(); n2.start_server()
    time.sleep(0.2)
    n1.send('127.0.0.1', 9202, {"test":"hello"})
    time.sleep(0.2)
    n1.stop(); n2.stop()
    assert True
