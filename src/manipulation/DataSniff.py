'''
    @author - mrdrivingduck
    @version - 2019.01.30
    @function - 
        To sniff a 802.11 data frame.
        Filter all retransmission frame.
'''

import os
from scapy.layers.dot11 import Dot11, Dot11ProbeResp, Dot11Elt, Dot11Beacon
from scapy.sendrecv import sniff

count = 0

def callback(packet):
    global count
    if packet.haslayer(Dot11):
        if packet.addr2 == "ba:09:87:65:43:21" and packet.addr1 == "12:34:56:78:90:ab":
            if not "retry" in packet.sprintf("%Dot11.FCfield%"):
                print(packet.show(), count)
                count += 1

iface = "kismon0"
channel = 1

os.system("iwconfig " + iface + " channel " + str(channel))
sniff(prn=callback, iface=iface)
