import argparse
from multiprocessing import Process
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import signal
import threading

def add_network(pckt, known_networks):
        # Check to see if it's a hidden SSID (this could be resolved later using out Deauth attack)
        essid = pckt[Dot11Elt].info if '\x00' not in pckt[Dot11Elt].info and pckt[Dot11Elt].info != '' else 'Hidden SSID'
        bssid = pckt[Dot11].addr3
        # This insight was included in airoscapy.py (http://www.thesprawl.org/projects/airoscapy/)
        channel = int(ord(pckt[Dot11Elt:3].info))
        if bssid not in known_networks:
                known_networks[bssid] = ( essid, channel )
                print "{0:5}\t{1:30}\t{2:30}".format(channel, essid, bssid)


# Channel hopper - This code is very similar to that found in airoscapy.py (http://www.thesprawl.org/projects/airoscapy/)
def channel_hopper(interface):
        while True:
                try:
                        channel = random.randrange(1,13)
                        os.system("iwconfig %s channel %d" % (interface, channel))
                        time.sleep(1)
                except KeyboardInterrupt:
                        break

def stop_channel_hop(signal, frame):
        # set the stop_sniff variable to True to stop the sniffer
        global stop_sniff
        stop_sniff = True
        channel_hop.terminate()
        channel_hop.join()

def keep_sniffing(pckt):
        return stop_sniff

if __name__ == "__main__":
        parser = argparse.ArgumentParser(description='aircommand.py - Utilize many wireless security features using the Scapy python module')
        parser.add_argument('-i', '--interface', dest='interface', type=str, required=True, help='Interface to use for sniffing and packet injection')
        args = parser.parse_args()
        networks = {}
        stop_sniff = False
        print 'Press CTRL+c to stop sniffing..'
        print '='*100 + '\n{0:5}\t{1:30}\t{2:30}\n'.format('Channel','ESSID','BSSID') + '='*100
        channel_hop = Process(target = channel_hopper, args=(args.interface,))
        channel_hop.start()
        signal.signal(signal.SIGINT, stop_channel_hop)
        # Sniff Beacon and Probe Response frames to extract AP info
        sniff( lfilter = lambda x: (x.haslayer(Dot11Beacon) or x.haslayer(Dot11ProbeResp)), stop_filter=keep_sniffing, prn=lambda x: add_network(x,networks) )