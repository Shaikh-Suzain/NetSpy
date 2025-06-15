from scapy.all import rdpcap,TCP,IP,DNSQR
from collections import defaultdict

def detect_suspicious(pcap_file):
    packets=rdpcap(pcap_file)
    syn_counts=defaultdict(int)
    dns_requests=[]

    for pkt in packets:
        if pkt.haslayer(IP):
            ip_src=pkt[IP].src
            if pkt.haslayer(TCP):
                if pkt[TCP].flags & 0x02:#syn flag
                    syn_counts[ip_src]+=1
            
            if pkt.haslayer(DNSQR):
                dns_requests.append(pkt[DNSQR].qname.decode())
    suspicious_ips = {ip: count for ip, count in syn_counts.items() if count >= 1}
    print("=== SYN Packet Count (Potential Port Scan) ===")
    for ip,count in syn_counts.items():
        if count>=1:
            print(f"{ip}->{count} SYNs")
    
    print("\n=== DNS Requests ===")
    for q in dns_requests[:10]:
        print(q)
    
    with open("C:/Users/Suzain/Desktop/NetSpy/outputs/suspicious_report.txt","w") as f:
        f.write("SYN Packet Count (Potential Port Scan):\n")
        for ip,count in suspicious_ips.items():
            f.write(f"{ip}-> {count} SYNs\n")

detect_suspicious("C:/Users/Suzain/Desktop/NetSpy/captures/testcapture.pcap")

