#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#


from sys import argv, exit
from os import path
from scapy.all import *
from ipaddr import IPNetwork, IPAddress, IPv4Network
import logging


# Disable verbose
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0

# and the new Scapy Ping Command (function)
def ping(host, count=3):
  packet = IP(dst=host)/ICMP()
  for x in range(count):
     ans = sr1(packet)
     ans.show2()

# for sending all types and codes of icmp, simply build 2 for loops and send the packet. On the Taget side, you can sniff, what packet's are recived.
# set target ip
def ping_any_type(host):
    # define ip and icmp
    ip = IP()
    icmp = ICMP()
    # set the destinaion IP to the target
    ip.dst = host
    # create 2 casade loops for sending the icmp packet
    for i_type in range(0,256):
      for i_code in range(0,256):
        icmp.type = i_type
        icmp.code = i_code
        print i_type,i_code
        send(ip/icmp)


def icmp_ping(host, count=5):
    return srloop(IP(dst=host)/ICMP(),count=count)


def arp_ping(host, timeout=2):
    answered,unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=host),timeout=timeout,verbose=False)
    if len(answered) > 0:
        print(answered[0][0].getlayer(ARP).pdst, "is up")
    elif len(unanswered) > 0:
        print(unanswered[0].getlayer(ARP).pdst, " is down")


def ping_cdr(cdr, timeout=2):
    for ip in IPNetwork(cdr).iterhosts():
        # ip_list.append(IPAddress(ip))
        packet = IP(dst=str(ip), ttl=20)/ICMP()
        reply = sr1(packet, timeout=timeout)
        if not (reply is None):
             print reply.dst, "is online"
        else:
             print "Timeout waiting for %s" % packet[IP].dst


if __name__ == '__main__':
    ping("1.0.0.1",4)
    # ping_any_type("1.0.0.1")
    #icmp_ping("1.0.0.1")
    # ping_cdr("1.0.0.1/24")
