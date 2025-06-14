from scapy.all import sniff,IP

def packet_callback(packet):

    if IP in packet:
        summary=packet.summary()
        print(f"[Packet Summary]{summary}")
        src=packet[IP].src
        dst=packet[IP].dst
        proto=packet[IP].proto
        proto_name={6:"TCP",17:"UDP",1:"ICMP"}.get(proto,str(proto))
        print(f"{src}-> {dst} : {proto_name}")

sniff(iface="Wi-Fi",filter="ip",prn=packet_callback,count=3)