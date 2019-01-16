'''
    @author Mr Dk.
    @version 2019.1.2
    @function
        Use 'traceroute()' to perform traceroute.
        'ans' contains all received packets
        'unans' contails all unreceived packets
            Use 's, r = ans.res' to get sent and received packets
            Use 'summary()' or 'show()' to see packets.
            Use 'sprintf("%...%")' to see specific field.
'''


from scapy.layers.inet import traceroute


ans, unans = traceroute("www.baidu.com")

for s, r in ans.res:
    print(s.summary(), s.sprintf("%IP.ttl%"))
    print(r.summary())

