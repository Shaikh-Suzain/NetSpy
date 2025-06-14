from scapy.all import rdpcap

def summarize_dns_http(pcap_file):
    packets = rdpcap(pcap_file)
    print(f"[*] Loaded {len(packets)} packets")

    for pkt in packets:
        if pkt.haslayer("IP"):
            src = pkt["IP"].src
            dst = pkt["IP"].dst

            # DNS Detection
            if pkt.haslayer("DNS") and pkt.haslayer("UDP"):
                print("\n[DNS Packet]")
                print("Source IP:", src)
                print("Destination IP:", dst)
                if pkt["DNS"].qd:
                    print("Query for:", pkt["DNS"].qd.qname.decode())

            # HTTP Detection
            elif pkt.haslayer("TCP") and pkt.haslayer("Raw"):
                if pkt["TCP"].dport == 80 or pkt["TCP"].sport == 80:
                    payload = pkt["Raw"].load
                    if b"GET" in payload or b"POST" in payload:
                        print("\n[HTTP Packet]")
                        print("Source IP:", src)
                        print("Destination IP:", dst)
                        print("Request Line:", payload.split(b'\r\n')[0].decode(errors="ignore"))

if __name__ == "__main__":
    summarize_dns_http("C:/Users/Suzain/Desktop/NetSpy/captures/day2_mixed_capture.pcap")

