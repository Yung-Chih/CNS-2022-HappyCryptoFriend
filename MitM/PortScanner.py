import time
from scapy.all import *



def try_tcp_connect(ip, port):
    success = False

    packet = IP(dst=ip) / TCP(dport=port, flags='S') # [SYN] to ip:port
    resp = sr1(packet, timeout=0.5, verbose=0) # Suppose ip is under the same LAN

    success = resp != None and resp.haslayer(TCP) and resp[TCP].flags == 0x12

    if success:
        reset_packet = IP(dst=ip) / TCP(dport=port, flags='R')
        sr1(reset_packet, timeout=0.5, verbose = 0)

    return success

if __name__ == "__main__":
    target = '192.168.1.71'
    
    st = time.time()
    for port in range(1, 65535+1):
        if try_tcp_connect(target, port):
            print('Port[%d] is open'%(port))

    dt = time.time() - st
    print("Scan complete in %d (sec)"%(dt) )