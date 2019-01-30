'''
    @author - mrdrivingduck
    @version - 2019.01.30
    @function - 
        To send a 802.11 data frame.
'''

import os
from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11Beacon, RadioTap
from scapy.sendrecv import send, sendp

dot11 = Dot11()
dot11.type = 2
dot11.subtype = 0
dot11.FCfield = "to-DS"
dot11.addr1 = "12:34:56:78:90:ab"  # destination
dot11.addr2 = "ba:09:87:65:43:21"  # sender
dot11.addr3 = "ba:09:87:65:43:21"  # sender

# Constructing packet
frame = RadioTap() / dot11
print(frame.show())

iface = "kismon1"
channel = 1

os.system("iwconfig " + iface + " channel " + str(channel))
# sendp(frame, iface=iface, inter=0.1, loop=1, count=1)
sendp(frame, iface=iface)
