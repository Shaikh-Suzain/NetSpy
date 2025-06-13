from scapy.all import sniff,wrpcap
def capture_packets():
    print("[*] Starting packet capture... Press Ctrl+C to stop.")
    packets=sniff(filter="tcp port 80",count=20)
    for pkt in packets:
        print("\nPacket Layers:")
        if pkt.haslayer("IP"):
            print("Source IP: ",pkt["IP"].src)
            print("Destination IP:", pkt["IP"].dst)
        if pkt.haslayer("TCP"):
            print("Source Port:", pkt["TCP"].sport)
            print("Destination Port:", pkt["TCP"].dport)
    print("[*] Capture complete. Saving to file...")

    wrpcap("captures/day2_http_capture.pcap",packets)
    print("[*] Packets saved to captures/day2_http_capture.pcap")

if __name__=="__main__":
    capture_packets()