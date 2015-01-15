#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

__author__ = '090h'
__license__ = 'GPL'

from scapy.all import *
from scapy.layers.inet import IP, UDP


def udp_ping(host, port=0):
    """ UDP Ping """
    # If all else fails there is always UDP Ping which will produce ICMP Port unreachable errors
    # from live hosts. Here you can pick any port which is most likely to be closed,
    # such as port 0:
    ans, unans = sr(IP(dst=host)/UDP(dport=port))

    # Once again, results can be collected with this command:
    ans.summary(lambda(s, r): r.sprintf("%IP.src% is alive"))

if __name__ == '__main__':
    pass