


import os
from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11Beacon, RadioTap
from scapy.sendrecv import send, sendp

SSID = "11223344"

elt = Dot11Elt()
elt.ID = 0
elt.info = SSID
elt.len = len(SSID)

beacon = Dot11Beacon(cap="ESS+privacy", timestamp=100000000, beacon_interval=10000)

dot11 = Dot11()
dot11.type = 0
# dot11.subtype = 8
# dot11.addr1 = "12:34:56:78:90:ab"  # destination
dot11.addr1 = "ff:ff:ff:ff:ff:ff"
dot11.addr2 = "ba:09:87:65:43:21"  # sender
dot11.addr3 = "ba:09:87:65:43:21"  # sender

# Constructing packet
frame = RadioTap() / dot11 / beacon / elt
print(frame.show())

iface = "kismon1"
channel = 1

os.system("iwconfig " + iface + " channel " + str(channel))
# sendp(frame, iface=iface, inter=0.1, loop=1, count=1)
sendp(frame, iface=iface)
