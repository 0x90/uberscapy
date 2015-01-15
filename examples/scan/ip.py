#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#


from sys import argv

from scapy.all import *
from scapy.layers.inet import IP


def ip_scan(host):
    # A lower level IP Scan can be used to enumerate supported protocols:
    ans,unans = sr(IP(dst=host, proto=(0, 255))/"SCAPY", retry=2)

if __name__ == '__main__':
    ip_scan(argv[1])