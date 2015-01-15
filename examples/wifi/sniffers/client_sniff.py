#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

from sys import argv
from scapy.all import *
from scapy.layers.dot11 import Dot11

PROBE_REQ_TYPE = 0
PROBE_REQ_SUBTYPE = 4
unique_ssids = []


def packet_handler(pkt):
    # check if Beacon frame
    if pkt.type == PROBE_REQ_TYPE and pkt.subtype == PROBE_REQ_SUBTYPE:
        # null probe removal
        if pkt.info not in unique_ssids:
            unique_ssids.append(pkt.info)
            print("New probed SSID: %s" % pkt.info)

sniff(iface=argv[1], prn=packet_handler, lfilter=lambda pkt: pkt.haslayer(Dot11), store=0)