import os
from scapy.layers.dot11 import Dot11, Dot11ProbeResp, LLC
from scapy.sendrecv import sniff


def callback(packet):

    if packet.haslayer(Dot11):

        # iPhone -> Surface
        if "Data" in packet.sprintf("%Dot11.type%"):
            if packet.addr2 == "b8:c1:11:02:b7:05" and packet.addr1 == "c6:9d:ed:9f:8d:d8":
                print(packet.summary())

iface = "kismon0"
channel = 1

os.system("iwconfig " + iface + " channel " + str(channel))
sniff(prn=callback, iface=iface)
