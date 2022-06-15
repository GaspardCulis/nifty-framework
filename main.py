import pydivert
from nifty.protocols.ntp import *
import struct
import datetime


TARGET_DATETIME = datetime.datetime(2003, 8, 26, 16, 30, 0)


# Capture only TCP packets to port 80, i.e. HTTP requests.
w = pydivert.WinDivert("udp.DstPort == 123 and inbound")

w.open()  # packets will be captured from now on

packet = w.recv()  # read a single packet
new = insert_receive_timestamp(TARGET_DATETIME, packet.payload)
ts = extract_transmit_timestamp(new)
print(f"ref id : {ts}")

w.send(packet)  # re-inject the packet into the network stack

w.close()  # stop capturing packets
