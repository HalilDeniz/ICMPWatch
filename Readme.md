# ICMPWatch: ICMP Packet Sniffer
ICMP Packet Sniffer is a Python program that allows you to capture and analyze ICMP (Internet Control Message Protocol) packets on a network interface. It provides detailed information about the captured packets, including source and destination IP addresses, MAC addresses, ICMP type, payload data, and more. The program can also store the captured packets in a SQLite database and save them in a pcap format.

<img src="source/icmpwatch.png">

## Features

- Capture and analyze ICMP Echo Request and Echo Reply packets.
- Display detailed information about each ICMP packet, including source and destination IP addresses, MAC addresses, packet size, ICMP type, and payload content.
- Save captured packet information to a text file.
- Store captured packet information in an SQLite database.
- Save captured packets to a PCAP file for further analysis.
- Support for custom packet filtering based on source and destination IP addresses.
- Colorful console output using ANSI escape codes.
- User-friendly command-line interface.

## Requirements

- Python 3.7+
- scapy 2.4.5 or higher
- colorama 0.4.4 or higher

## Installation

1. Clone this repository:

```bash
git clone https://github.com/HalilDeniz/ICMPWatch.git
```

2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Usage

```
python ICMPWatch.py [-h] [-v] [-t TIMEOUT] [-f FILTER] [-o OUTPUT] [--type {0,8}] [--src-ip SRC_IP] [--dst-ip DST_IP] -i INTERFACE [-db] [-c CAPTURE]
```

- `-v` or `--verbose`: Show verbose packet details.
- `-t` or `--timeout`: Sniffing timeout in seconds (default is 300 seconds).
- `-f` or `--filter`: BPF filter for packet sniffing (default is "icmp").
- `-o` or `--output`: Output file to save captured packets.
- `--type`: ICMP packet type to filter (0: Echo Reply, 8: Echo Request).
- `--src-ip`: Source IP address to filter.
- `--dst-ip`: Destination IP address to filter.
- `-i` or `--interface`: Network interface to capture packets (required).
- `-db` or `--database`: Store captured packets in an SQLite database.
- `-c` or `--capture`: Capture file to save packets in pcap format.


Press `Ctrl+C` to stop the sniffing process.

## Examples

- Capture ICMP packets on the "eth0" interface:
```bash
python icmpwatch.py -i eth0
```

- Sniff ICMP traffic on interface "eth0" and save the results to a file:
```bash
python dnssnif.py -i eth0 -o icmp_results.txt
```

- Filtering by Source and Destination IP:
```bash
python icmpwatch.py -i eth0 --src-ip 192.168.1.10 --dst-ip 192.168.1.20
```

- Filtering ICMP Echo Requests:
```bash
python icmpwatch.py -i eth0 --type 8
```

- Saving Captured Packets
```bash
python icmpwatch.py -i eth0 -c captured_packets.pcap
```

## License

ICMPWatch is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for educational and testing purposes only. It should not be used for any malicious activities.

## Contact

- Linktr [halildeniz](https://linktr.ee/halildeniz)
- DenizHalil [DenizHalil](https://denizhalil.com)
- LinkedIn: [Halil Ibrahim Deniz](https://www.linkedin.com/in/halil-ibrahim-deniz/)
- TryHackMe: [Halilovic](https://tryhackme.com/p/halilovic)
- Instagram: [deniz.halil333](https://www.instagram.com/deniz.halil333/)
- YouTube: [Halil Deniz](https://www.youtube.com/c/HalilDeniz)
- Email: halildeniz313@gmail.com


## 💰 You can help me by Donating
Thank you for considering supporting me! Your support enables me to dedicate more time and effort to creating useful tools like DNSWatch and developing new projects. By contributing, you're not only helping me improve existing tools but also inspiring new ideas and innovations. Your support plays a vital role in the growth of this project and future endeavors. Together, let's continue building and learning. Thank you!"<br>
[![BuyMeACoffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/halildeniz) 
[![Patreon](https://img.shields.io/badge/Patreon-F96854?style=for-the-badge&logo=patreon&logoColor=white)](https://patreon.com/denizhalil) 

  
