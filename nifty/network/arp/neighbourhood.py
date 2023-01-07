from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
from ..utils import check_root, get_if_cidr
import nifty.config as config
import nmap

class NetworkDevice():
    def __init__(self, ip: str, mac: str | None):
        self.ip: str = ip
        self.mac: str | None = mac

    def __str__(self) -> str:
        return "{"+f"ip: {self.ip}, mac: {self.mac}"+"}"

    def __repr__(self):
        return self.__str__()

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