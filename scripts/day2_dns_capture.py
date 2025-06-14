from scapy.all import sniff,wrpcap

def packet_capture():
    packet = sniff(filter="udp port 53 or tcp port 80", count=50)
    summary=packet.summary()
    print(f"[Packet Summary]:\n{summary}")
    print("Capture Completed")

    wrpcap("captures/day2_mixed_capture.pcap",packet)

if __name__=="__main__":
    packet_capture()
