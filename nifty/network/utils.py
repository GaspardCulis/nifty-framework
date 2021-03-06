from scapy.all import *


def get_mac(IP: str, interface="wlan0"):
    conf.verb = 0
    ans, uans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=IP), timeout=2,
                    iface=interface, inter=0.1)
    for snd, rcv in ans:
        return rcv.sprintf(r"%Ether.src%")


def get_router_ip():
    return conf.route.route("0.0.0.0")[2]


def get_interfaces():
    out = list()
    for iface in list(IFACES.data.values()):
        out.append(iface.description)
    return out
