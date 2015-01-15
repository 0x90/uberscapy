#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# http://cloud101.eu/blog/2013/03/25/discovering-hidden-ssid-with-wireshark-and-scapy/

from scapy.all import *
import re
#from csvCreator import CSV

aps = dict()
headers = ['channel','enc','bssid','ssid'] #The headers for the CSV file


class CSV(object):
    csvFile = None
    fileName = ''

    def __init__(self,fileName,headers):
        self.fileName = fileName
        self.prepareCSVFile(headers)

    def prepareCSVFile(self,headers):
        self.csvFile = open(self.fileName, 'w')
        headerString = self.prepareValues(headers)
        self.writeToCSV(headerString)

    def prepareValues(self,valueList):
        line = str()
        x = len(valueList)
        for item in valueList:
            print x
            line = line + str(item)
            if x != 1:
                line = line + ','
            else:
                line = line + '\n'
            x = x - 1
        return line

    def addToCSV(self,valueList):
        valueLine = self.prepareValues(valueList)
        self.writeToCSV(valueLine)

    def writeToCSV(self,line):
        self.csvFile.write(line)

csvFile = CSV('sniffed.csv',headers) #Create a new CSV file with the previously defined headers

def sniffAP(p):
    detectAP(p)


def detectAP(p):
    if ( (p.haslayer(Dot11Beacon) or p.haslayer(Dot11ProbeResp)) and not aps.has_key(p[Dot11].addr3)):
        ssid = p[Dot11Elt].info
        bssid = p[Dot11].addr3
        channel = int( ord(p[Dot11Elt:3].info))
        capability = p.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                {Dot11ProbeResp:%Dot11ProbeResp.cap%}")

        # Check for encrypted networks
        if re.search("privacy", capability): enc = 'Y'
        else: enc = 'N'

        # Save discovered AP
        aps[p[Dot11].addr3] = enc

        # Write the results to the CSV file  
        csvFile.addToCSV( [int(channel), enc, bssid, ssid] )


if __name__ == '__main__':
    sniff(iface = "mon0",prn = sniffAP)