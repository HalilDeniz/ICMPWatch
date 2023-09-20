#!/usr/bin/env python3
import argparse
from datetime import datetime
from scapy.all import sniff, ICMP, Ether
from colorama import init, Fore, Style
from scapy.utils import wrpcap
from source.icmpdata import ICMPDatabase
from source.icmpfiglet import icmpfiglet

class PacketSniffer:
    def __init__(self, interface, verbose, timeout, filter_expr, output_file, use_db, capture_file):
        self.interface = interface
        self.verbose = verbose
        self.timeout = timeout
        self.filter_expr = filter_expr
        self.capture_file = capture_file
        self.output_file = output_file
        self.use_db = use_db
        self.total_packets = 0
        self.echo_request_count = 0
        self.echo_reply_count = 0
        self.total_bytes_sent = 0
        self.total_bytes_received = 0

        if self.use_db:
            self.db = ICMPDatabase()


    def icmp_packet_handler(self, packet):
        icmp_type_str = ""

        if packet.haslayer(ICMP) and packet.haslayer(Ether):
            self.total_packets += 1
            icmp_packet = packet.getlayer(ICMP)
            ip_header = packet.getlayer('IP')
            ether_header = packet.getlayer(Ether)
                    #ip
            src_ip               = ip_header.src
            dst_ip               = ip_header.dst
            ip_version           = ip_header.version
            ttl                  = ip_header.ttl if ip_header.ttl else "N/A"
                    #ethernet
            src_mac              = ether_header.src
            dst_mac              = ether_header.dst
            packet_size          = len(packet)
                    #icmp
            icmp_type            = icmp_packet.type
            icmp_echo_identifier = icmp_packet.id
            icmp_echo_sequence   = icmp_packet.seq
            icmp_checksum        = icmp_packet.chksum

            if icmp_type == 8:  # ICMP Echo Request
                icmp_type_str = "Echo Request"
                self.echo_request_count += 1
                self.total_bytes_sent += packet_size
            elif icmp_type == 0:  # ICMP Echo Reply
                icmp_type_str = "Echo Reply"
                self.echo_reply_count += 1
                self.total_bytes_received += packet_size

            timestamp = datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S')

            print(f"{Fore.CYAN}\tICMP Packet Detected:{Style.RESET_ALL}")
            print(f"{Fore.GREEN}Source IP      :{Style.RESET_ALL} {src_ip}")
            print(f"{Fore.GREEN}Destination IP :{Style.RESET_ALL} {dst_ip}")
            print(f"{Fore.GREEN}Source MAC     :{Style.RESET_ALL} {src_mac}")
            print(f"{Fore.GREEN}Destination MAC:{Style.RESET_ALL} {dst_mac}")
            print(f"{Fore.GREEN}IP Version     :{Style.RESET_ALL} IPv{ip_version}")
            print(f"{Fore.GREEN}TTL            :{Style.RESET_ALL} {ttl}")
            print(f"{Fore.GREEN}Checksum       :{Style.RESET_ALL} {icmp_checksum}")
            print(f"{Fore.GREEN}Packet Size    :{Style.RESET_ALL} {packet_size} bytes")
            print(f"{Fore.GREEN}Passing Time   :{Style.RESET_ALL} {timestamp}")
            print(f"{Fore.GREEN}ICMP Type      :{Style.RESET_ALL} {icmp_type_str}")
            print(f"{Fore.GREEN}Echo Identifier:{Style.RESET_ALL} {icmp_echo_identifier}")
            print(f"{Fore.GREEN}Echo Sequence  :{Style.RESET_ALL} {icmp_echo_sequence}")

            if icmp_packet.payload:
                payload = icmp_packet.payload.load
                payload_hex = ' '.join(format(byte, '02X') for byte in payload)
                print(f"{Fore.GREEN}Payload (Hex)  :{Style.RESET_ALL} {payload_hex}")

                try:
                    payload_content = payload.decode("utf-8")
                    print(f"{Fore.GREEN}Payload (ASCII):{Style.RESET_ALL} {payload_content}")
                except UnicodeDecodeError:
                    payload_content = "Non-UTF-8 Payload"
                    print(f"{Fore.GREEN}Payload (ASCII):{Style.RESET_ALL} {payload_content}")

            else:
                payload_hex = "No Payload"
                payload_content = "No Payload"
            print("-" * 40)

            if icmp_packet.type == 8:  # ICMP Echo Request
                self.echo_request_count += 1
                self.total_bytes_sent += packet_size
            elif icmp_packet.type == 0:  # ICMP Echo Reply
                self.echo_reply_count += 1
                self.total_bytes_received += packet_size

            if self.output_file:
                with open(self.output_file, "a") as f:
                    f.write(f"Source IP      : {src_ip}\n")
                    f.write(f"Destination IP : {dst_ip}\n")
                    f.write(f"Source MAC     : {src_mac}\n")
                    f.write(f"Destination MAC: {dst_mac}\n")
                    f.write(f"IP Version     : IPv{ip_version}\n")
                    f.write(f"TTL            : {ttl}\n")  # TTL değerini ekle
                    f.write(f"Checksum       : {icmp_checksum}\n")
                    f.write(f"Packet Size    : {packet_size} bytes\n")
                    f.write(f"Passing Time   : {timestamp}\n")
                    f.write(f"ICMP Type      : {icmp_type_str}\n")
                    f.write(f"Echo Identifier: {icmp_echo_identifier}\n")
                    f.write(f"Echo Sequence  : {icmp_echo_sequence}\n")
                    f.write(f"{'-'*40}\n")

            if self.capture_file:  # Eğer capture_file tanımlıysa .pcap dosyasına kaydet
                self.start_capture([packet])

            if self.use_db:  # Veritabanına kayıt için bu bloğu ekleyin
                data_to_store = (timestamp, src_ip, dst_ip, src_mac, dst_mac, f"IPv{ip_version}", ttl, icmp_checksum, str(packet_size), icmp_type_str, str(icmp_echo_identifier), str(icmp_echo_sequence), payload_hex, payload_content)
                self.db.insert_packet(data_to_store)


    def start_capture(self, packets_to_capture):
        wrpcap(self.capture_file, packets_to_capture)
    def print_statistics(self):
        print(f"{Fore.YELLOW}\tICMP Packet Sniffing Statistics:{Style.RESET_ALL}")
        print(f"Total Packets       : {self.total_packets}")
        print(f"Echo Request Packets: {self.echo_request_count}")
        print(f"Echo Reply Packets  : {self.echo_reply_count}")
        print(f"Total Bytes Sent    : {self.total_bytes_sent} bytes")
        print(f"Total Bytes Received: {self.total_bytes_received} bytes")

    def start_sniffing(self):
        f"\t\{icmpfiglet()}"
        try:
            packets = sniff(iface=self.interface, filter=self.filter_expr, timeout=self.timeout, prn=self.icmp_packet_handler)
            if self.capture_file:
                self.start_capture(packets)
        except KeyboardInterrupt:
            print("Sniffing stopped by user.")
        finally:
            if self.use_db:
                self.db.close()


def main():
    init(autoreset=True)  # colorama otomatik renk sıfırlama
    parser = argparse.ArgumentParser(description="ICMP Packet Sniffer")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show verbose packet details")
    parser.add_argument("-t", "--timeout", type=int, default=300, help="Sniffing timeout in seconds")
    parser.add_argument("-f", "--filter", default="icmp", help="BPF filter for packet sniffing")
    parser.add_argument("-o", "--output", help="Output file to save captured packets")
    parser.add_argument("--type", type=int, choices=[0, 8], help="ICMP packet type to filter (0: Echo Reply, 8: Echo Request)")
    parser.add_argument("--src-ip", help="Source IP address to filter")
    parser.add_argument("--dst-ip", help="Destination IP address to filter")
    parser.add_argument("-i", "--interface", required=True, help="Network interface to capture packets")
    parser.add_argument("-db", "--database", action="store_true", help="Store captured packets in SQLite database")
    parser.add_argument("-c", "--capture", help="Capture file to save packets in pcap format")
    args = parser.parse_args()

    sniffer = PacketSniffer(args.interface, args.verbose, args.timeout, args.filter, args.output, args.database, args.capture)
    sniffer.start_sniffing()
    sniffer.print_statistics()


if __name__ == "__main__":
    main()
