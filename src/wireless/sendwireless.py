'''
    @author mrdrivingduck
    @version 2019.1.11
    @function
        To build and send 802.11 packets.
        Use 'send()' to send packets in layer 3.
        Use 'sendp()' to send packets in layer 2.

        The 'iface' for sending should be running at monitor mode.

        The packet needs to be consturcted before sending.

        If the network is down using 'airmon-ng', use 'kismet' instead.
'''

from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11Beacon, RadioTap
from scapy.sendrecv import send, sendp

dot11 = Dot11()
dot11.type = 2
dot11.subtype = 4
dot11.addr1 = "ff:ff:ff:ff:ff:ff"
dot11.addr2 = "00:c0:ca:7e:a6:42"
dot11.addr3 = "00:c0:ca:7e:a6:42"

frame = RadioTap()/dot11
print(frame.summary())

sendp(frame, iface="kismon0", inter=0.1, loop=1)
