



import os
from scapy.layers.dot11 import Dot11, Dot11ProbeResp, Dot11Elt
from scapy.sendrecv import sniff

def callback(packet):
    if packet.haslayer(Dot11):
        if packet.addr2 == "00:c0:ca:7e:a6:42":
            print(packet.summary())

iface = "kismon0"
channel = 1

os.system("iwconfig " + iface + " channel " + str(channel))
sniff(prn=callback, iface=iface)
