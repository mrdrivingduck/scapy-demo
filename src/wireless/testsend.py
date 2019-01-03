

from scapy.layers.dot11 import Dot11, Dot11ProbeResp, LLC
from scapy.sendrecv import sniff


def callback(packet):
    if Dot11 in packet:
        if "Data" in packet.sprintf("%Dot11.type%"):
            if "12:34:56:78:9A:BC" in packet.addr1:
                print(packet.show())

    

sniff(prn=callback, iface="wlan0mon")
