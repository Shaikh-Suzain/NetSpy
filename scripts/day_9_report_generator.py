from scapy.all import rdpcap, TCP, IP, DNSQR
from collections import defaultdict
import matplotlib.pyplot as plt

def analyze_and_report(pcap_file):
    packets = rdpcap(pcap_file)
    syn_counts = defaultdict(int)
    dns_requests = []

    for pkt in packets:
        if pkt.haslayer(IP):
            ip_src = pkt[IP].src
            if pkt.haslayer(TCP) and pkt[TCP].flags & 0x02:
                syn_counts[ip_src] += 1
            if pkt.haslayer(DNSQR):
                dns_requests.append(pkt[DNSQR].qname.decode())

    suspicious_ips = {ip: count for ip, count in syn_counts.items() if count >= 1}

    # Save bar chart of top suspicious IPs
    if suspicious_ips:
        plt.figure(figsize=(10, 5))
        plt.bar(suspicious_ips.keys(), suspicious_ips.values(), color='crimson')
        plt.title("Suspicious SYN Packet Counts")
        plt.ylabel("Count")
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig("C:/Users/Suzain/Desktop/NetSpy/screenshots/report_syn_chart.png")
        plt.show()

    # Write to text report
    with open("C:/Users/Suzain/Desktop/NetSpy/outputs/final_report.txt", "w") as f:
        f.write("=== SYN Packet Count (Potential Port Scan) ===\n")
        for ip, count in suspicious_ips.items():
            f.write(f"{ip} -> {count} SYNs\n")
        f.write("\n=== First 10 DNS Requests ===\n")
        for q in dns_requests[:10]:
            f.write(f"{q}\n")

    print("[+] Report saved as final_report.txt and chart saved as report_syn_chart.png")

# Example use
analyze_and_report("C:/Users/Suzain/Desktop/NetSpy/captures/testcapture.pcap")
