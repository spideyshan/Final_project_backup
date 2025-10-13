# src/p2p/manager.py
from p2p.node import P2PNode

def create_two_nodes():
    n1 = P2PNode('127.0.0.1', 9101, node_name='node1')
    n2 = P2PNode('127.0.0.1', 9102, node_name='node2')
    n1.start_server()
    n2.start_server()
    return n1, n2
