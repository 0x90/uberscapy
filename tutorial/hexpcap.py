#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# Hexfump packets from PCAP file.

__author__ = '090h'
__license__ = 'GPL'

from sys import argv, exit
from os import path
from scapy.all import *


def hexdump_pcap(filename):
    if not path.exists(filename):
        return

    pkts = sniff(offline=filename)
    for pkt in pkts:
        pkt.hexdump()
        raw_input('Press any key to continue.')

if __name__ == '__main__':
    if len(argv) == 1:
        print('Usage:\n\thexpcap.py <pcap_file>')
        exit(1)

    hexdump_pcap(argv)