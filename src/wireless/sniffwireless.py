'''
    @author Mr Dk.
    @version 2019.1.3
    @function
        Use 'sniff(iface="wlan0mon")' to sniff wireless traffic.
            Wireless interface should be at monitor mode.
            'Dot11' is the basic class, which has types of 
                'Management', 'Control', Data' and 'Reserved'.
            'Dot11' has many subtypes:
                PrismHeader
                RadioTap
                PPI
                    Dot11
                        Dot11QoS - [DATA]
                            LLC
                        Dot11WEP - [DATA]
                        Dot11AssoReq
                            Dot11Elt
                        Dot11AssoResp
                            Dot11Elt
                        Dot11ReassoReq
                            Dot11Elt
                        Dot11ReassoResp
                            Dot11Elt
                        Dot11ProbeReq
                            Dot11Elt
                        Dot11ProbeResp
                            Dot11Elt
                        Dot11Beacon
                            Dot11Elt
                        Dot11ATIM
                        Dot11Disas
                        Dot11Auth
                            Dot11Elt
                        Dot11Deauth
                        Dot11Ack - [CONTROL]
'''

import os
from scapy.layers.dot11 import Dot11, Dot11ProbeResp, LLC
from scapy.sendrecv import sniff


def callback(packet):
    # print(packet.show())
    # print(packet.summary())
    if packet.haslayer(Dot11):
        # frameType = packet.sprintf("%Dot11.type%")
        # typeNum = packet.sprintf("%type%")
        # if "Data" in frameType:
        #     print(packet.show())

        if packet.addr2 == "00:c0:ca:7e:a6:42":
            print(packet.summary())

iface = "kismon0"
channel = 1

os.system("iwconfig " + iface + " channel " + str(channel))
sniff(prn=callback, iface=iface)
