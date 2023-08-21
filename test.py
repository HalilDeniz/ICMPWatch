#!/usr/bin/env python3
from scapy.all import IP, ICMP, sr1, send

def send_icmp_echo_request(destination_ip):
    icmp_request = IP(dst=destination_ip)/ICMP()
    reply = sr1(icmp_request, timeout=2, verbose=False)
    return reply

def send_hello_icmp(destination_ip):
    hello_icmp = IP(dst=destination_ip)/ICMP()/"hello icmp"
    reply = sr1(hello_icmp, timeout=2, verbose=False)
    return reply

if __name__ == "__main__":
    target_ip = "google.com"

    print(f"Sending ICMP Echo Request to {target_ip}...")
    reply = send_icmp_echo_request(target_ip)

    if reply:
        print(f"ICMP Echo Reply received from {reply.src}")
        print(f"Sending 'hello icmp' to {target_ip}...")
        hello_reply = send_hello_icmp(target_ip)
        if hello_reply:
            print(f"Received reply to 'hello icmp': {hello_reply[0].load.decode('utf-8')}")
        else:
            print("No reply received for 'hello icmp'.")
    else:
        print("No ICMP Echo Reply received.")
