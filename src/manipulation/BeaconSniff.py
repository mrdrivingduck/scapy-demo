'''
    @author - mrdrivingduck
    @version - 2019.01.30
    @function
        To sniff a beacon frame.
'''

import os
from scapy.layers.dot11 import Dot11, Dot11ProbeResp, Dot11Elt, Dot11Beacon
from scapy.sendrecv import sniff

def callback(packet):
    if packet.haslayer(Dot11):
        if packet.addr2 == "ba:09:87:65:43:21" and packet.addr1 == "ff:ff:ff:ff:ff:ff":
            print(packet.show())

iface = "kismon0"
channel = 1

os.system("iwconfig " + iface + " channel " + str(channel))
sniff(prn=callback, iface=iface)
