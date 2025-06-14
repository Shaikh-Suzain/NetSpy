# 🕵️‍♀️ NetSpy: A Beginner-Friendly Network Packet Sniffer & Analyzer

NetSpy is a Python-based project designed for learning **network sniffing, protocol analysis, and visualization** using **Scapy** and **Wireshark**. It captures, filters, saves, and visualizes network traffic step by step.

---

## 📁 Project Structure

NetSpy/
├── captures/ # Saved .pcap and .pcapng files from each day
├── screenshots/ # Visual outputs, screenshots, bar graphs
├── scripts/ # Python scripts for each day (sniffers, analyzers, visualizers)
├── README.md # This file
├── .gitignore # Ignores temp files and captures from version control
├── requirements.txt # List of Python packages


---

## 🧠 Learning Journey

### ✅ Day 1 – Basic Packet Sniffing

- Used Scapy’s `sniff()` to capture packets on the local network
- Displayed simple packet summaries (protocol, source, destination)
- Introduced how to save `.pcap` files
- 🔧 Scripts:
  - `scripts/day1_sniffer.py`
  - `scripts/day1_hw_sniffer.py`

### ✅ Day 2 – Filtering and Saving Specific Protocols

- Captured only **DNS (port 53)** and **HTTP (port 80)** traffic using filters
- Parsed packets using `.haslayer("IP")` and `.haslayer("TCP"/"UDP")`
- Saved captures to `captures/day2_dns_capture.pcap` and `day2_http_capture.pcap`
- Wrote a script to combine & filter DNS + HTTP in one capture
- 🔧 Scripts:
  - `scripts/day2_dns_capture.py`
  - `scripts/day2_filtered_saver.py`
- 📁 Output:
  - `captures/day2_dns_capture.pcap`
  - `captures/day2_http_capture.pcap`
  - `captures/day2_mixed_capture.pcap`

### ✅ Day 3 – Parsing & Summarizing Captures

- Opened `.pcap` files using Scapy’s `rdpcap()`
- Parsed DNS requests (`dns.qd.qname`) and HTTP requests (`Raw` layer)
- Printed summarized results from `day2_mixed_capture.pcap`
- Learned to extract readable data from deeper packet layers
- 🔧 Script:
  - `scripts/day3_dns_http_summary.py`

### ✅ Day 4 – Visualizing Traffic (Basic Stats)

- Used `matplotlib` to create a bar chart of protocol counts
- Counted TCP/UDP/ICMP from capture file and visualized results
- Introduced `Counter()` from `collections` for frequency count
- 🔧 Script:
  - `scripts/day4_protocol_visualizer.py`
- 🖼️ Output:
  - `screenshots/day4_protocol_chart.png` (if saved manually)

---

## 🛠️ How to Run

Make sure to activate your virtual environment and install dependencies:

```bash
pip install -r requirements.txt

To sniff or visualize packets:


python scripts/day1_sniffer.py
python scripts/day2_dns_capture.py
python scripts/day3_dns_http_summary.py
python scripts/day4_protocol_visualizer.py