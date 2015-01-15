#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

__author__ = '090h'
__license__ = 'GPL'

from sys import argv, exit
from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.ntp import NTP

send(IP(dst=argv[1])/fuzz(UDP()/NTP(version=4)), loop=1)