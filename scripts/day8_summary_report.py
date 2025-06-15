from scapy.all import rdpcap, IP
from collections import Counter

def summarize_traffic(pcap_file):
    packets = rdpcap(pcap_file)
    ip_counter=Counter()
    protocol_counter=Counter()

    for pkt in packets:
        if pkt.haslayer(IP):
            ip_counter[pkt[IP].src]+=1
            proto=pkt[IP].proto
            protocol_counter[proto]+=1

    with open("final_summary.txt","w")as f:
        f.write(f"Total Packets: {len(packets)}\n\n")
        f.write("Top IP Talkers:\n")
        for ip,count in ip_counter.most_common(5):
            f.write(f"{ip}:{count}\n")

        f.write("\nProtocol Usage:\n")
        for proto, count in protocol_counter.items():
            f.write(f"Protocol {proto}: {count}\n")


summarize_traffic("C:/Users/Suzain/Desktop/NetSpy/captures/day2_mixed_capture.pcap")