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
                    Dot11QoS
                        LLC
                    Dot11
                        LLC
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
                        Dot11Ack
                        Dot11Elt
                            Dot11Elt
'''

from scapy.layers.dot11 import *


def callback(packet):
    # print(packet.show())
    # if packet.haslayer(Dot11):
    #     frameType = packet.sprintf("%Dot11.type%")
    #     typeNum = packet.sprintf("%type%")
    #     if "Data" in frameType:
    #         print(packet.summary())
    if Dot11 in packet:
        if Dot11ProbeResp in packet:
            packet.show()


sniff(prn=callback, iface="wlan0mon")
