'''
    @author - mrdrivingduck
    @version - 2019.1.16
    @function - 
        Sniffing the packets from illegal Evil Twin AP to legitimate AP
'''

import os, time
from scapy.layers.dot11 import Dot11, Dot11ProbeResp, LLC
from scapy.sendrecv import sniff

iface = "kismon1"
channel = 1
evilTwinSTAMAC = "00:87:34:50:38:d3"
realDestiMAC = "94:d9:b3:14:d0:e8"

def callback(packet):
    if packet.haslayer(Dot11):
        if packet.addr2 == evilTwinSTAMAC and packet.addr1 == realDestiMAC:
            frameType = packet.sprintf("%Dot11.type%")
            subType = packet.sprintf("%Dot11.subtype%")
            print(time.time(), frameType, subType, packet.addr2, ">", packet.addr1)

os.system("iwconfig " + iface + " channel " + str(channel))
sniff(prn=callback, iface=iface)
