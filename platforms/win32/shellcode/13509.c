/*

 PEB!NtGlobalFlags ( 14 BYTES )
 Author: Koshi
 Description: Uses PEB method to determine whether a debugger is
	      attached to the running proccess or not. No 9x. :(
 Length: 14 Bytes
 Registers Used: EAX,ESI,ESP
 Compiled: jpXV34dd3v09Fh

*/

/*

 00401000 >   6A 70          PUSH 70
 00401002     58             POP EAX
 00401003     56             PUSH ESI
 00401004     333464         XOR ESI,DWORD PTR SS:[ESP]
 00401007     64:3376 30     XOR ESI,DWORD PTR FS:[ESI+30]
 0040100B     3946 68        CMP DWORD PTR DS:[ESI+68],EAX
			     JE DebuggerPresent ( If equal debugger attached )
*/

unsigned char Shellcode[] =
{"\x6A\x70\x58\x56\x33\x34\x64"
"\x64\x33\x76\x30\x39\x46\x68"};



int main( int argc, char *argv[] )
{
 printf( "Shellcode is %u bytes.\n", sizeof(Shellcode)-1 );
 printf( Shellcode, sizeof(Shellcode) );
 return 0;
}

// milw0rm.com [2009-02-24]