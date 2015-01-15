#!/usr/bin/env python

from scapy.all import Ether,sniff

#while True:
#    a=sniff(count=1)
#    if a[0].fields['type'] == 0x8088:
#        print a[0]

sniff(prn=lambda x: "from %s -> %s" %(x.src, x['Raw'].load), lfilter=lambda x: x.haslayer(Ether) and x.fields['type'] == 0x3333)