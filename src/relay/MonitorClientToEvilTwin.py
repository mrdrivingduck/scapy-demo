'''
    @author - mrdrivingduck
    @version - 2019.1.16
    @funtion - 
        Sniffing the packets from illegal to Evil Twin AP
'''

import os, time
from scapy.layers.dot11 import Dot11, Dot11ProbeResp, LLC
from scapy.sendrecv import sniff

iface = "kismon0"
channel = 11
victimMAC = "c4:9d:ed:9f:89:d9"
evilTwinAP = "bc:f6:85:2c:1e:0d"

def callback(packet):
    if packet.haslayer(Dot11):
        if packet.addr2 == victimMAC and packet.addr1 == evilTwinAP:
            frameType = packet.sprintf("%Dot11.type%")
            subType = packet.sprintf("%Dot11.subtype%")
            print(time.time(), frameType, subType, packet.addr2, ">", packet.addr1)

os.system("iwconfig " + iface + " channel " + str(channel))
sniff(prn=callback, iface=iface)
