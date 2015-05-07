__author__ = 'shzigel'

import dpkt
import socket

# open pcap file
f = open(r"C:\Users\shzigel\Desktop\Security_Team\Challenges\PCAP Challenge\challange.pcap", "rb")
# f = open(r"C:\Users\shzigel\Desktop\Security_Team\Challenges\PCAP Challenge\ynet.pcap", "rb")
pr = dpkt.pcap.Reader(f)

# statistics dict
stat_dict = {}

# for each packet in pcap, insert packet to temp array
for ts, buf in pr:
    eth = dpkt.ethernet.Ethernet(buf)

    if eth.type == dpkt.ethernet.ETH_TYPE_IP:
        ip = eth.data

        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)

        if ip.p == dpkt.ip.IP_PROTO_TCP:
            tcp = ip.data

            src_port = tcp.sport
            dst_port = tcp.dport

            if tcp.dport == 80 and len(tcp.data) > 0:
                hdr = tcp.data

                # if http header is incomplete
                if not hdr.endswith("\r\n\r\n"):
                    connection_list = (src_ip,src_port,dst_ip,dst_port)

                    if connection_list in stat_dict:
                        if stat_dict[connection_list] > 10:
                            print "slow loris detected! attacker ip is " + str(connection_list[0])
                            break
                        else:
                            stat_dict[connection_list] += 1
                    else:
                        stat_dict[connection_list] = 1

# if ip in dict:
            # if dict[ip][incomplete_header_counter] == 10 (saw 10 times incomplete headers from the same ip)
                # block ip
            # else: dict[ip][incomplete_header_counter]++
        # else: dict[ip][incomplete_header_counter] = 0

print stat_dict
# disclaimers:
    # should clean dictionary on live traffic to avoid exhausting the memory
    # a real system should include statistics on good traffic in order to set proper treshholds
    # more data should be used on real traffic such as user / ISP / geoIP rating
    # on live traffic, the system can also be inspected and reviewed for
    # resources exahusting to combine better protection
    # we can also combine interval between requests

    # check the push!!!
    # fragmentation safe
f.close()