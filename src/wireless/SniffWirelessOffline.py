'''
    @author Mr Dk.
    @version 2019.2.23
    @function
        Use 'sniff(iface="wlan0mon")' to sniff wireless traffic.
            Wireless interface should be at monitor mode.
'''

import os
from scapy.layers.dot11 import Dot11, Dot11ProbeResp, LLC
from scapy.sendrecv import sniff
from scapy.utils import wrpcap

pkts = []

def callback(packet):
    # print(packet.show())
    # print(packet.summary())
    if packet.haslayer(Dot11):
        # frameType = packet.sprintf("%Dot11.type%")
        # typeNum = packet.sprintf("%type%")
        # if "Data" in frameType:
        #     print(packet.show())packet.summary()

        if packet.addr2 == "9c:a6:15:12:07:2e" or packet.addr1 == "9c:a6:15:12:07:2e":
            print(packet.summary())
            pkts.append(packet)


iface = "kismon0"
# channel = 1

# os.system("iwconfig " + iface + " channel " + str(channel))
sniff(iface=iface, timeout=20)
wrpcap("data/temp.pcap", pkts)