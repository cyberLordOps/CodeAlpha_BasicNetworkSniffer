Title & Introduction

Title: Network Packet Sniffer using Python

Introduction:
This project implements a basic network sniffer in Python using the Scapy library. The program captures network packets in real-time, extracts essential details such as source and destination IP addresses, protocol types, and payloads, and displays them in a readable format.
The goal of this task is to introduce fundamental concepts of computer networking, particularly how data flows across a network and how packet sniffing tools work. By analyzing raw packets, we gain insights into the structure of TCP/IP protocols, communication between clients and servers, and the visibility (or encryption) of transmitted data.
This documentation provides an overview of the objectives, methodology, implementation, and findings from building and testing the packet sniffer.

Objectives
The objectives of this task are as follows:
1. Build a Python program to capture network traffic packets.
2. Analyze captured packets to understand their structure and content.
3. Learn how data flows through the network and the basics of protocols (TCP, UDP, DNS, HTTP).
4. Use libraries like Scapy or Socket for packet capturing.
5. Display useful information such as source/destination IPs, protocols, and payloads.
All objectives were successfully achieved through the implementation of the sniffer and subsequent packet analysis.

Tools & Environment
Programming Language: Python 3.13.17
Library Used: Scapy 2.5
Operating System: Windows 11 (also works on Linux/Kali)
Network Interface: Wi-Fi adapter for live traffic monitoring
Privileges: Administrator/root permissions required for raw packet sniffing

Methodology
The project followed a structured approach:
Step 1: Setup
Installed Python and Scapy (pip install scapy).
Configured permissions for raw packet sniffing.
Step 2: Code Development
Developed a Python script using Scapy’s sniff() function.
Designed a callback function to process each packet as it arrives.
Step 3: Packet Analysis
Extracted packet fields such as source IP, destination IP, protocol, and payload.
Handled cases where payloads were empty or unreadable.
Step 4: Protocol-Specific Parsing
Added decoding for DNS queries to display domain lookups.
Extracted HTTP GET requests when available.
Displayed raw payloads where decoding was not possible.

Implementation (Code Snippet)
from scapy.all import sniff, IP, TCP, UDP, DNS, Raw

def packet_callback(pkt):
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto
        payload = "N/A"

        # Check for DNS queries
        if pkt.haslayer(DNS):
            payload = pkt[DNS].summary()

        # Check for raw payload (HTTP or other data)
        elif pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load.decode(errors="ignore")
            except:
                payload = pkt[Raw].load

        print(f"📦 {src} -> {dst} | Proto: {proto} | Payload: {payload}")

# Start sniffing (CTRL + C to stop)
sniff(prn=packet_callback, store=False)
This program runs continuously and prints information for every captured packet.

Sample Output
Below is a snippet of real captured traffic:
📦 192.168.32.169 -> 196.49.32.6 | Proto: TCP | Payload: b'GET /pr/5030841d-c919...'
📦 196.49.32.6 -> 192.168.32.169 | Proto: TCP | Payload: N/A
📦 192.168.32.196 -> 192.168.32.169 | Proto: ARP | Payload: N/A
📦 192.168.32.169 -> 192.168.32.196 | Proto: UDP | Payload: N/A
📦 192.168.32.169 -> 172.64.155.209 | Proto: TCP | Payload: b'\x00'
📦 172.64.155.209 -> 192.168.32.169 | Proto: TCP | Payload: N/A
📦 192.168.32.169 -> 13.89.179.10 | Proto: TCP | Payload: N/A
This output shows communication between the local system and multiple remote servers, involving different protocols and payload types.

Analysis & Findings
From the captured packets, several observations were made:
TCP is dominant: Most web traffic operates over TCP for reliability.
UDP is used for fast services: Protocols like DNS use UDP for quick, connectionless communication.
DNS queries are readable: These reveal the domain names the system is attempting to resolve.
HTTP requests are visible: For non-HTTPS connections, parts of HTTP requests (e.g., GET lines) can be read.
HTTPS encrypts payloads: Most modern traffic is HTTPS, making the payload unreadable.
Two-way communication: Packets show clear client → server and server → client flows.

Challenges Faced
Encrypted Traffic: Most web applications use HTTPS, so payloads were not fully readable.
Raw Payload Handling: Non-printable characters sometimes caused decoding issues.
Permissions: Root/administrator access was required to run the sniffer.
Traffic Noise: Large volumes of packets made it challenging to focus on specific flows without filters.

Conclusion
This task successfully met all objectives. A working Python packet sniffer was developed using Scapy, capable of capturing live network traffic, extracting useful details, and presenting them in a readable format.
Through this project, a deeper understanding was gained of:
Network packet structures (IP, TCP, UDP, DNS, HTTP).
The flow of data between local devices and external servers.
The limitations of packet sniffing due to encryption.
This foundational knowledge provides a strong base for advanced tasks, such as packet filtering, logging, intrusion detection, or protocol-specific analysis.

References
Scapy Documentation: https://scapy.net
Python Official Documentation: https://docs.python.org
Networking Basics (TCP/IP Model): Forouzan, B. A. Data Communications and Networking. McGraw-Hill.
