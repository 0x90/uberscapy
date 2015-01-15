#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

__author__ = '090h'
__license__ = 'GPL'

from sys import argv

from scapy.all import *
from scapy.layers.inet import IP, ICMP


def icmp_ping(host):
    """ ICMP Ping """

    # Classical ICMP Ping can be emulated using the following command:
    ans, unans = sr(IP(dst=host)/ICMP())

    # Information on live hosts can be collected with the following request:
    ans.summary(lambda (s, r): r.sprintf("%IP.src% is alive"))

if __name__ == '__main__':
    icmp_ping(argv[1])