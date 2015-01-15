#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

__author__ = '090h'
__license__ = 'GPL'

from sys import argv
from scapy.all import *
from scapy.layers.dot11 import Dot11

sniff(iface='mon0', prn=lambda x: x.hexdump(), lfilter=lambda x: x.haslayer(Dot11), store=False)

