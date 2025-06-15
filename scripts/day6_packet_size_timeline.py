from scapy.all import rdpcap
import matplotlib.pyplot as plt

def packet_size_over_time(pcap_file):
    packets = rdpcap(pcap_file)

    times=[]
    sizes=[]

    for pkt in packets:
        times.append(pkt.time)
        sizes.append(len(pkt))

    plt.plot(times,sizes,marker='o',linestyle='-',color='green')
    plt.title("Packet Sizes Over Time")
    plt.xlabel("Timestamp")
    plt.ylabel("Packet Size (bytes)")
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    packet_size_over_time("C:/Users/Suzain/Desktop/NetSpy/captures/day2_mixed_capture.pcap")