from scapy.all import sniff,wrpcap

print("[*] Capturing different packet types")

packets=sniff(count=100,timeout=90)

wrpcap("C:/Users/Suzain/Desktop/NetSpy/captures/day7_Variety_capture.pcap",packets)

print("[*] Saved as day7_Variety_capture.pcap")