import pyshark

cap = pyshark.LiveCapture(interface="eth0",bpf_filter="udp port 53")

cap.sniff(packet_count=10)


def print_dns_info(pkt):
    if pkt.dns.qry_name:
        print "DNS Request from %s: %s" % (pkt.ip.src, pkt.dns.qry_name)
    elif pkt.dns.resp_name:
        print "DNS Response from %s: %s" % (pkt.ip.src, pkt.dns.resp_name)

cap.apply_on_packets(print_dns_info, timeout=100)

class pysharkSniffer():
    import pyshark
    out_string = ''
    i = 1

    cap = pyshark.LiveCapture(interface='et0')

    cap.sniff(packet_count=5)

    for pkt in cap:

        out_file = open("Eavesdrop_Data.txt" , 'w')
        out_string += "Packet #         " + str(i)
        out_string += '\n'
        out_string += str(pkt)
        out_string += "\n"
        out_file.write(out_string)
        i = i+1
    cap.close()
