#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

from sys import argv
from scapy.all import *


sniff(iface=argv[1], prn=lambda x: x.hexdump(), store=False, count=20)

