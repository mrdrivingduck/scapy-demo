'''
    @author - mrdrivingduck
    @version - 2019.1.16
    @funtion - 
        Sniffing the packets from illegal to Evil Twin AP
'''

import os
from scapy.layers.dot11 import Dot11, Dot11ProbeResp, LLC
from scapy.sendrecv import sniff

iface = "kismon0"
channel = 1
evilTwinMAC = "00:00:00:00:00:00"

def callback(packet):
    if packet.haslayer(Dot11):
        if packet.addr1 == evilTwinMAC:
            print(packet.summary())

os.system("iwconfig " + iface + " channel " + str(channel))
sniff(prn=callback, iface=iface)
