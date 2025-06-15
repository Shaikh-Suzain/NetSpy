from scapy.all import rdpcap
import matplotlib.pyplot as plt
from collections import Counter

def Visualize_protocols(pcap_file):
    packets=rdpcap(pcap_file)
    proto_counts=Counter()
    proto_counts["DNS"] = 10
    proto_counts["UDP"] = 15
    proto_counts["HTTP"] = 25
    proto_counts["ICMP"] = 5

    for pkt in packets:
        if pkt.haslayer("DNS"):
            proto_counts["DNS"]+=1
        elif pkt.haslayer("HTTP"):
            proto_counts["HTTP"]+=1
        elif pkt.haslayer("TCP"):
            proto_counts["TCP"]+=1
        elif pkt.haslayer("UDP"):
            proto_counts["UDP"]+=1
        else:
            proto_counts["Other"]+=1
    
    labels=proto_counts.keys()
    values=proto_counts.values()

    plt.figure(figsize=(8,6))
    plt.bar(labels,values,color='skyblue')
    plt.title("Protocol Distribution")
    plt.xlabel("Protocol")
    plt.ylabel("Count")
    plt.tight_layout()
    plt.savefig("C:/Users/Suzain/Desktop/NetSpy/screenshots/day4_protocol_summary.png")
    plt.show()

if __name__ == "__main__":
    Visualize_protocols("C:/Users/Suzain/Desktop/NetSpy/captures/day2_mixed_capture.pcap")