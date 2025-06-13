from scapy.all import sniff
from scapy.all import get_if_list

def packet_callback(packet):
    print(packet.summary())
    print(get_if_list())
print("Sniffing packets... Press Ctrl+C to stop.")
sniff(count=10,prn=packet_callback)