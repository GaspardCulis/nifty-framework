from scapy.all import Ether, srp, ARP, conf, os, IFACES, get_if_addr
import nifty.config as config
from warnings import warn
import netifaces
import ipaddress

def get_mac(ip: str, interface=config.interface) -> str:
    warn("This function is deprecated. Use scapy's getmacbyip instead.", DeprecationWarning, stacklevel=2)
    conf.verb = 0
    ans, uans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2,
                    iface=interface, inter=0.1)
    for snd, rcv in ans:
        return rcv.sprintf(r"%Ether.src%")


def get_router_ip() -> str:
    return conf.route.route("0.0.0.0")[2]


def get_interfaces() -> list[str]:
    out = list()
    for iface in list(IFACES.data.values()):
        out.append(iface.description)
    return out

def check_root():
    if os.geteuid() != 0:
        print("You need to have root privileges to run this script.")
        print("Please try again, this time using 'sudo'. Exiting.")
        exit()

def get_if_cidr(interface = config.interface) -> str:
    addresses = netifaces.ifaddresses(interface)
    # Convert IP and netmask to CIDR, example: 192.168.12.42 & 255.255.255.0 -> 192.168.12.0/24
    return str(ipaddress.IPv4Interface(f"{addresses[netifaces.AF_INET][0]['addr']}/{addresses[netifaces.AF_INET][0]['netmask']}"))
