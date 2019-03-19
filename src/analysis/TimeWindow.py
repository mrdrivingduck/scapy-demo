'''
    @author Mr Dk.
    @version 2019.3.19
    @function
        Use 'rdpcap()' to read packet file captured by Wireshark
        Use 'pkt.time' to get packet receiving time in ms
        Use 'pkt.len' to get RadioTap dummy length
        Use 'len(pkt)' to get whole frame length
'''

from scapy.utils import rdpcap
from scapy.layers.dot11 import RadioTap

all_packets = rdpcap('data/evil-twin-20190318-part8.pcapng')
client_packets = []
ap_packets = []

for i in range(0, len(all_packets)):
    if 'c6:9d:ed:9f:8d:d8' in all_packets[i].addr1:
        client_packets.append(all_packets[i])
    else:
        ap_packets.append(all_packets[i])
    # if 'c6:9d:ed:9f:8d:d8' in all_packets[i].addr1:
    #     ap_packets.append(all_packets[i])
    # else:
    #     client_packets.append(all_packets[i])

client_packets_count = len(client_packets)
ap_packets_count = len(ap_packets)

window = 200

hit = 0

for i in range(0, client_packets_count):
    for j in range(0, ap_packets_count):
        if ap_packets[j].time <= client_packets[i].time:
            continue
        if ap_packets[j].time > client_packets[i].time + window:
            break
        ap_frame_len = len(ap_packets[j]) - ap_packets[j].len
        client_frame_len = len(client_packets[i]) - client_packets[i].len
        if ap_frame_len == client_frame_len:
            hit += 1
            break

print(hit / client_packets_count)


# for i in range(0, count):
#     if pkt[i].source 
#     length = len(pkts[i])
    # for j in range(i+1, count):
    # print(pkts[i].show())