from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
from ..utils import check_root, get_if_addr
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

def arp_scan(iface=config.interface, cidr_range="auto") -> list[NetworkDevice]:
    check_root()


    if cidr_range == "auto":
        ip = get_if_addr(iface)
        cidr_range = ip.split(".")
        cidr_range = ".".join(cidr_range[:-1]) + ".0/24"   

    nm = nmap.PortScanner()

    #scan the network
    nm.scan(hosts=cidr_range, arguments='-sn')

    # create a list of devices on the network
    devices = []

    # iterate through the hosts and add their IP and MAC addresses to the list
    for host in nm.all_hosts():
        devices.append(NetworkDevice(host, 'mac' in nm[host]['addresses'] and nm[host]['addresses']['mac'] or None))

    return devices