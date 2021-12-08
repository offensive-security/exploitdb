# Exploit Title: FLIR AX8 Thermal Camera 1.32.16 - Hard-Coded Credentials
# Author: Gjoko 'LiquidWorm' Krstic @zeroscience
# Date: 2018-10-14
# Vendor: FLIR Systems, Inc
# Product web page: https://www.flir.com
# Affected version: Firmware: 1.32.16, 1.17.13, OS: neco_v1.8-0-g7ffe5b3
# Hardware: Flir Systems Neco Board
# Tested on: GNU/Linux 3.0.35-flir+gfd883a0 (armv7l), lighttpd/1.4.33, PHP/5.4.14
# References:
# Advisory ID: ZSL-2018-5494
# Advisory URL: https://www.zeroscience.mk/en/vulnerabilities/ZSL-2018-5494.php

# Desc: The devices utilizes hard-coded and credentials within its Linux distribution
# image. These sets of credentials (SSH) are never exposed to the end-user and cannot
# be changed through any normal operation of the camera. Attacker could exploit this
# vulnerability by logging in using the default credentials for the web panel or gain
# shell access.

# Hard-coded SSH access:
# ----------------------

fliruser:3vlig
root:hello

# Default web creds:
# ------------------

admin:admin
user:user
viewer:viewer
service:???
developer:???