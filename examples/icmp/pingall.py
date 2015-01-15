#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

__author__ = '090h'
__license__ = 'GPL'

from sys import argv, exit
from scapy.all import *
from scapy.layers.inet import IP, ICMP
import logging


# Disable verbose
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0


for ip in range(0, 256):
    pkt = IP(dst="192.168.0." + str(ip), ttl=20)/ICMP()
    reply = sr1(pkt, timeout=2)
    if reply is None:
        print("Timeout waiting for %s" % pkt[IP].dst)
    else:
        print(reply.dst, "is online")
