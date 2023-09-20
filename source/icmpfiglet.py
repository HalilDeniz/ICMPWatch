import pyfiglet
from colorama import init, Fore

#Start Colorama
init(autoreset=True)

def icmpfiglet():
    metin = "ICMP Packet Sniffer started..."
    figlet_yazi = pyfiglet.figlet_format(metin, font="slant")


    return print(Fore.GREEN + figlet_yazi)