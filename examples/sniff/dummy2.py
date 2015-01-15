#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

__author__ = '090h'
__license__ = 'GPL'

from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon

sniff(iface='mon0', prn=lambda x: x.summary(), lfilter=lambda x: x.haslayer(Dot11Beacon), store=False, count=20)

