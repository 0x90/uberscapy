#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

__author__ = '090h'
__license__ = 'GPL'

from sys import argv
from scapy.all import *
from scapy.layers.inet import IP, UDP


ans, unans = sr(IP(dst=argv[1])/UDP(dport=[(1, 65535)]), inter=0.5, retry=10, timeout=1)
ans.nsummary()