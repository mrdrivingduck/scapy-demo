import os
from scapy.layers.dot11 import Dot11, Dot11ProbeResp, LLC
from scapy.sendrecv import sniff


def callback(packet):

    if packet.haslayer(Dot11):

        # Surface -> AP
        if "Data" in packet.sprintf("%Dot11.type%"):
            if packet.addr2 == "c4:9d:ed:9f:89:d9" and packet.addr1 == "94:d9:b3:14:d0:e8":
                print(packet.summary())

iface = "kismon1"
channel = 1

os.system("iwconfig " + iface + " channel " + str(channel))
sniff(prn=callback, iface=iface)
