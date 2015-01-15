#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

__author__ = '090h'
__license__ = 'GPL'

from sys import argv

from scapy.all import *
from scapy.layers.inet import IP, TCP


def tcp_ping(host, port=80):
    """ TCP Ping """

    # In cases where ICMP echo requests are blocked, we can still use various TCP Pings
    # such as TCP SYN Ping below:
    ans, unans = sr(IP(dst=host)/TCP(dport=port, flags="S"))

    # Any response to our probes will indicate a live host. We can collect results with the following command:
    ans.summary(lambda(s, r): r.sprintf("%IP.src% is alive"))

if __name__ == '__main__':
    tcp_ping(argv[1])