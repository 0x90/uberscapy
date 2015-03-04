#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# Simple LAN monitor

__author__ = '@090h'

from scapy.all import *
from scapy.layers.inet import ARP, UDP


def lan_monitor(pkt):
    if ARP in pkt and pkt[ARP].op in (1, 2): #who-has or is-at
        return pkt.sprintf("%ARP.hwsrc% %ARP.psrc%")
    if UDP in pkt:
        return pkt.sprintf("%DHCP.options%")

if __name__ == '__main__':
    sniff(prn=lan_monitor, filter="arp or (udp and (port 67 or 68))", store=0)