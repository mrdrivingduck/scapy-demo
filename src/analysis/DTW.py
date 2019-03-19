'''
    @author Mr Dk.
    @version 2019.3.19
    @function
        Use 'rdpcap()' to read packet file captured by Wireshark
        Use 'pkt.time' to get packet receiving time in ms
        Use 'pkt.len' to get RadioTap dummy length
        Use 'len(pkt)' to get whole frame length
        Use dtw to calculate distance between time series
'''

from scapy.utils import rdpcap
from scapy.layers.dot11 import RadioTap
import numpy as np

all_packets = rdpcap('data/evil-twin-20190318-part1.pcapng')
client_packets = []
ap_packets = []

for i in range(0, len(all_packets)):
    time = all_packets[i].time
    length = len(all_packets[i]) - all_packets[i].len
    point = [time, length]
    if '50:5b:c2:d8:d1:21' in all_packets[i].addr2:
        client_packets.append(point)
    else:
        ap_packets.append(point)

x = np.array(client_packets)
y = np.array(ap_packets)

from scipy.spatial.distance import euclidean
from fastdtw import fastdtw

distance, path = fastdtw(x, y, dist=euclidean)
print(distance)