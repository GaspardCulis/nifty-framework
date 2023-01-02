from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
from ..utils import check_root, get_if_addr
import nmap

def arp_scan(iface="wlan0", cidr_range="auto") -> list:
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
        print(host)
        device = {
            "ip": host,
            "mac": 'mac' in nm[host]['addresses'] and nm[host]['addresses']['mac'] or None
        }
        devices.append(device)

    return devices