#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

__author__ = '090h'
__license__ = 'GPL'

from sys import argv

from scapy.all import *
from scapy.layers.inet import IP, TCP


def seq_plot(host):
    a, b = sr(IP(dst=host)/TCP(sport=[RandShort()]*1000))
    a.plot(lambda x: x[1].id)


if __name__ == '__main__':
    seq_plot(argv[1])