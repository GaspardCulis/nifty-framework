import scapy.all as scapy
from time import sleep
from ..utils import get_mac


class ARPSpoofer():
    def __init__(self, target_ip, interface="wlan0"):
        self.target_ip = target_ip
        self.target_mac = get_mac(target_ip, interface)
