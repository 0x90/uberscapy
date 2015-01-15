#!/usr/bin/env python
# -*- encoding: utf-8 -*-
#

__author__ = '090h'
__license__ = 'GPL'

from sys import argv, exit
from os import path, geteuid
from subprocess import Popen


def shell_exec(cmd):
    Popen(cmd, shell=True).wait()

# you can have a kind of FakeAP:
def fake_ap(essid, iface='wlan0', channel=1):
    '''
    Wireless frame injection
    Provided that your wireless card and driver are correctly configured for frame injection
    '''
    if geteuid() != 0:
        print('You must be root!')
        return
    shell_exec('ifconfig %s up' % iface).wait()
    shell_exec('iwpriv %s hostapd %s' % (iface, channel))
    shell_exec('ifconfig %sap up' % iface)

    sendp(Dot11(addr1="ff:ff:ff:ff:ff:ff",
                addr2=RandMAC(),
                addr3=RandMAC())/
          Dot11Beacon(cap="ESS")/
          Dot11Elt(ID="SSID",info=RandString(RandNum(1,50)))/
          Dot11Elt(ID="Rates",info='\x82\x84\x0b\x16')/
          Dot11Elt(ID="DSset",info="\x03")/
          Dot11Elt(ID="TIM",info="\x00\x01\x00\x00"),iface="wlan0ap",loop=1)

# Wireless sniffing
# The following command will display information similar to most wireless sniffers:
def scan_ap(iface='wlan0'):
    sniff(iface=iface,
          prn=lambda x: x.sprintf("{Dot11Beacon:%Dot11.addr3%\t%Dot11Beacon.info%\t%PrismHeader.channel%\tDot11Beacon.cap%}"))


if __name__ == '__main__':
    pass