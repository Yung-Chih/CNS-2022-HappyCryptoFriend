import sys
sys.path.append('../venv/lib/python3.8/site-packages')
print(sys.path)

from scapy.all import *
def process_packet(packet):
    print(packet)
    pass

if __name__ == "__main__":
    # This need permission!
    sniff(prn = process_packet, store=False, filter='tcp')