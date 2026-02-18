# src/attacks/mitm_demo.py
"""
MITM/sniff demo using Scapy. Run only in a controlled environment (VM/local lab).
On Windows, ensure Npcap is installed and run with admin rights if sniffing.
"""
from scapy.all import sniff, TCP, Raw

def packet_callback(pkt):
    if pkt.haslayer(Raw) and pkt.haslayer(TCP):
        try:
            payload = pkt[Raw].load.decode(errors='ignore')
        except:
            return
        if "secret" in payload.lower():
            print("[MITM] Found 'secret' in payload:", payload)

def start_sniff(interface=None, count=0):
    print("Starting sniff (Ctrl+C to stop). Interface:", interface)
    sniff(prn=packet_callback, iface=interface, filter="tcp", store=0, count=count)

if __name__ == "__main__":
    start_sniff()
