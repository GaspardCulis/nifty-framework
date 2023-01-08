from scapy.all import Ether, srp, ARP, conf, os, IFACES
import nifty.config as config
from warnings import warn
import netifaces
import ipaddress
from netfilterqueue import NetfilterQueue

def get_mac(ip: str, interface:str=None) -> str:
    warn("This function is deprecated. Use scapy's getmacbyip instead.", DeprecationWarning, stacklevel=2)
    if not interface:interface=config.interface
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

def get_if_cidr(interface:str=None) -> str:
    if not interface:interface=config.interface
    addresses = netifaces.ifaddresses(interface)
    # Convert IP and netmask to CIDR, example: 192.168.12.42 & 255.255.255.0 -> 192.168.12.0/24
    return str(ipaddress.IPv4Interface(f"{addresses[netifaces.AF_INET][0]['addr']}/{addresses[netifaces.AF_INET][0]['netmask']}"))

class MITM():
    
    _registered_queues = []

    def start(callback, interface:str=None, verbose=True):
        if not interface:interface=config.interface
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

