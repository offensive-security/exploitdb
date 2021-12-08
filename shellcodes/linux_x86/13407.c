/* writehello-core.c by Charles Stevenson <core@bokeoa.com>
 *
 * I made this as a chunk you can paste in to make modular remote
 * exploits.  I use it to see if my dup2_loop worked.  If you don't
 * get "Hello core!\n" back it's a good indicator your shell won't
 * be functional the way you'd like.
 */
char hellcode[] = /* write(0,"Hello core!\n",12); linux/x86 by core */
"\x31\xdb"              // xor  %ecx,%ecx
"\xf7\xe3"              // mul  %ecx
"\x53"                  // push %ecx
"\x68\x72\x65\x21\x0a"  // push $0xa216572
"\x68\x6f\x20\x63\x6f"  // push $0x6f63206f
"\x68\x48\x65\x6c\x6c"  // push $0x6c6c6548
"\xb2\x0c"              // mov  $0xc,%dl
"\x43"                  // inc  %ebx
"\x89\xe1"              // mov  %esp,%ecx
"\xb0\x04"              // mov  $0x4,%al
"\xcd\x80"              // int  $0x80
// not needed.. makes it exit cleanly
// 7 bytes _exit(1) ... 'cause we're nice >:) by core
"\x31\xc0"              // xor  %eax,%eax
"\x40"                  // inc  %eax
"\x89\xc3"              // mov  %eax,%ebx
"\xcd\x80"              // int  $0x80
;

int main(void)
{
  void (*shell)() = (void *)&hellcode;
  printf("%d byte (w/optional 7 byte exit) write(0,\"Hello core!\\n\",12); linux/x86 by core\n",
         strlen(hellcode));
  shell();
  return 0;
}

// milw0rm.com [2005-11-09]