# CodeAlpha_BasicNetworkSniffer
📌 Description

CodeAlpha_BasicNetworkSniffer is a minimalist packet-sniffing utility built in Python. It captures live network traffic at the transport and network layers and parses packet headers (IP, TCP/UDP, etc.) for protocol analysis, IP tracing, and port inspection.
Ideal for educational use, security testing, and low-level network debugging.


---

🎯 Objectives

Capture live network packets.

Analyze source/destination IPs, ports, and protocols.

Understand the flow of data across a network.

Provide a lightweight tool for learning packet sniffing basics.



---

🛠 Tools & Requirements

Language: Python 3.13.7

Library: Scapy

Works on Windows / Linux (may require admin/root privileges).



---

🚀 How to Run

1. Clone the repository:

git clone https://github.com/cyberLordOps/CodeAlpha_BasicNetworkSniffer.git
cd CodeAlpha_BasicNetworkSniffer


2. Install dependencies:

pip install scapy


3. Run the sniffer:

python sniffer.py




---

📖 Example Output

Source: 192.168.1.10 → Destination: 142.250.190.78 | Protocol: TCP | Port: 443
Source: 192.168.1.10 → Destination: 224.0.0.251   | Protocol: UDP | Port: 5353


---

📚 Additional Notes

HTTPS packets are encrypted; only metadata (IP, ports, protocol) is visible.

DNS queries and TCP handshakes are more readable.

Running requires admin/root privileges on most systems.



---

📂 Documentation

For detailed explanations (TCP/UDP breakdowns, DNS, HTTPS limitations, findings), see 👉 [Report] (REPORT.md) 


---

📜 License

This project is licensed under the MIT License – feel free to use and modify it for learning.


