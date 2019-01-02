'''
    @author Mr Dk.
    @version 2019.1.1
    @function
        Use 'sniff()' and a callback function to sniff.
        Use 'summary()' or 'show()' to see the packet.
        Use 'sprintf("%...%")' to get specific field
'''


from scapy.sendrecv import sniff
from scapy.layers.inet import TCP


def callback(packet):
    # print(packet.summary())
    # print(packet.show())
    if TCP in packet:
        print(packet[TCP].show())
        print(packet[TCP].summary())
        # src_port = int(packet.sprintf("%sport%"))
        # dst_port = int(packet.sprintf("%dport%"))
        # src_ip = packet.sprintf("%IP.src%")
        # dst_ip = packet.sprintf("%IP.dst%")
        # src_mac = packet.sprintf("%src%")
        # dst_mac = packet.sprintf("%dst%")
        # print(src_ip, src_port, dst_ip, dst_port, src_mac, dst_mac)


sniff(prn=callback)

