#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/kernel.h>
#include <string.h>
#include <sys/mman.h>
#include <linux/fd.h>

static int drive_selector(int head) {
            return (head << 2);
}

void fd_recalibrate(int fd) {
                struct floppy_raw_cmd raw_cmd;
                int tmp;

                raw_cmd.flags = FD_RAW_INTR;
                raw_cmd.cmd_count = 2;

                // set up the command
                raw_cmd.cmd[raw_cmd.cmd_count++] = 0x07;
                raw_cmd.cmd[raw_cmd.cmd_count++] = drive_selector(0);
                tmp = ioctl( fd, FDRAWCMD, &raw_cmd );
                printf("Status:%d\n",tmp);
}
int main(){
        printf("Start\n");
        char *d;
        struct floppy_raw_cmd *cmd;

        int fd;
        fd = open("/dev/fd0",O_RDWR | O_NDELAY);
        fd_recalibrate(fd);
        close(fd);
        printf("End\n");
        return 0;
}