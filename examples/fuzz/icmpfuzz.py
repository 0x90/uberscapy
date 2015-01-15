#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

__author__ = '090h'
__license__ = 'GPL'

from sys import argv, exit
from scapy.all import *
from scapy.layers.inet import IP, UDP, ICMP

send(IP(dst=argv[1])/fuzz(ICMP(code=0, seq=0, id=0)), loop=1)

