#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

__author__ = '090h'
__license__ = 'GPL'

from sys import argv, exit
from os import path
from sys import argv, exit
from os import path
from sys import argv, exit
from os import path

from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP


def ack_scan(host):
    ans, unans = sr(IP(dst=host)/TCP(dport=[80,666], flags="A"))
    # We can find unfiltered ports in answered packets:
    for s, r in ans:
        if s[TCP].dport == r[TCP].sport:
            print str(s[TCP].dport) + " is unfiltered"

    # Similarly, filtered ports can be found with unanswered packets:
    for s in unans:
        print str(s[TCP].dport) + " is filtered"

if __name__ == '__main__':
    pass