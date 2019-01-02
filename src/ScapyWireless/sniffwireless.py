

from scapy.layers.dot11 import *


def callback(packet):
    # print(packet.summary())
    print(packet.haslayer(Dot11))


sniff(prn=callback)
