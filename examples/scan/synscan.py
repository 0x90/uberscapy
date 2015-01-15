#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

__author__ = '090h'
__license__ = 'GPL'

from sys import argv, exit
from os import path
from scapy.all import *

# Classic SYN Scan can be initialized by executing the following command from Scapy’s prompt:
sr1(IP(dst="72.14.207.99")/TCP(dport=80,flags="S"))


# From the above output, we can see Google returned “SA” or SYN-ACK flags indicating an open port.
# Use either notations to scan ports 400 through 443 on the system:

sr(IP(dst="192.168.1.1")/TCP(sport=666,dport=(440,443),flags="S"))

# or

sr(IP(dst="192.168.1.1")/TCP(sport=RandShort(),dport=[440,441,442,443],flags="S"))

# In order to quickly review responses simply request a summary of collected packets:
ans,unans = _
ans.summary()
