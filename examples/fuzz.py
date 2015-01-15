#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

__author__ = '090h'
__license__ = 'GPL'

from scapy.all import *
from sys import argv


if __name__ == '__main__':
    send(IP(dst=argv[1])/fuzz(UDP()/NTP(version=4)), loop=1)