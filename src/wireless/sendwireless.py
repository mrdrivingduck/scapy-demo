'''
    @author mrdrivingduck
    @version 2019.1.3
    @function
        To build and send 802.11 packets.
        Use 'send()' to send packets in layer 3.
        Use 'sendp()' to send packets in layer 2.
'''

from scapy.layers.dot11 import Dot11, Dot11Ack
from scapy.sendrecv import send, sendp

pkt = Dot11()
pkt.type = 2
pkt.addr1 = "12:34:56:78:9A:BC"
pkt.addr2 = "CB:A9:97:65:43:21"
pkt.addr3 = "CB:A9:97:65:43:21"

print(pkt.show())
sendp(pkt, iface="wlan0mon", count=100)