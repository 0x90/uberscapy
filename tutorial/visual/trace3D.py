#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

__author__ = '090h'
__license__ = 'GPL'

from sys import argv, exit
from os import path
from scapy.all import *


def traceroute_graph():
    res, unans = traceroute(
        ["www.microsoft.com", "www.cisco.com", "www.yahoo.com", "www.wanadoo.fr", "www.pacsec.com"],
        dport=[80,443],
        maxttl=20,
        retry=-2)

    res.graph()                          # piped to ImageMagick's display program. Image below.
    # res.graph(type="ps",target="| lp")   # piped to postscript printer
    # res.graph(target="> /tmp/graph.svg") # saved to file

    res.trace3D()

if __name__ == '__main__':
    pass