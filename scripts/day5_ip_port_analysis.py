from scapy.all import rdpcap
from collections import Counter
import matplotlib.pyplot as plt


def analyze_ip_port(pcap_file):
    packets=rdpcap(pcap_file)
    src_ips=[]
    dst_ips=[]
    src_ports=[]
    dst_ports=[]

    for pkt in packets:
        if pkt.haslayer("IP"):
            src_ips.append(pkt["IP"].src)
            dst_ips.append(pkt["IP"].dst)
        if pkt.haslayer("TCP"):
            src_ports.append(pkt["TCP"].sport)
            dst_ports.append(pkt["TCP"].dport)


    print("\nTop 5 Source IPs:", Counter(src_ips).most_common(5))
    print("Top 5 Destination IPs:", Counter(dst_ips).most_common(5))
    print("Top 5 Source Ports:", Counter(src_ports).most_common(5))
    print("Top 5 Destination Ports:", Counter(dst_ports).most_common(5))

    top_ips=Counter(src_ips).most_common(5)
    if top_ips:
        ips,counts=zip(*top_ips)
        plt.bar(ips,counts,color="Red")
        plt.title("Top Source IPs")
        plt.xlabel("IP Address")
        plt.ylabel("Count")
        plt.tight_layout()
        plt.show()

if __name__ == "__main__":
    analyze_ip_port("C:/Users/Suzain/Desktop/NetSpy/captures/day7_Variety_capture.pcap")