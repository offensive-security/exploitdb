#!/usr/bin/python
#coding:utf-8

from scapy.all import DNS, DNSQR, IP, sr1, UDP, DNSRRTSIG, DNSRROPT

tsig = DNSRRTSIG(rrname="local-ddns", algo_name="hmac-sha256", rclass=255, mac_len=0, mac_data="", time_signed=0, fudge=300, error=16)

dns_req = IP(dst='127.0.0.1')/UDP(dport=53)/DNS(rd=1, ad=1, qd=DNSQR(qname='www.example.com'), ar=tsig)
answer = sr1(dns_req, verbose=0)

print(answer[DNS].summary())