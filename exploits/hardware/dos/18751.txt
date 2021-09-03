#######################################################################

                             Luigi Auriemma

Application:  Samsung devices with support for remote controllers
              http://www.samsung.com
Versions:     current
Platforms:    the vulnerable protocol is used on both TV and blue-ray
              devices so both of them should be vulnerable (my tests
              were performed only on a D6000 TV with the latest
              firmware); the following are the products listed on the
              iTunes section of the app but note that I have NOT
              tested them:
              - TV released in 2010 with Internet@TV feature
                Models greater than or equal to LCD 650, LED 6500 and PDP 6500
              - TV released in 2011 with AllShare feature
                Models greater than or equal to LCD 550, LED 5500 and PDP 5500
              - BD released in 2011 with Smart Hub feature
                Models greater than or equal to BD-Player D5300
                Models greater than or equal to BD-HTS D5000
                BD-AVR D7000
                BD-HDD Combo D6900/8200/8500/8900
Bugs:         A] Endless restarts
              B] Possible buffer-overflow
Exploitation: remote
Date:         19 Apr 2012
Author:       Luigi Auriemma
              e-mail: aluigi@autistici.org
              web:    aluigi.org


#######################################################################


1) Introduction
2) Bugs
3) The Code
4) Fix


#######################################################################

===============
1) Introduction
===============


All the current Samsung TV and BD systems can be controlled remotely
via iPad, Android and other software/devices supporting the protocol
used on TCP port 55000:

  http://itunes.apple.com/us/app/samsung-remote/id359580639
  https://play.google.com/store/apps/details?id=com.samsung.remoteTV

The vulnerabilities require only the Ethernet/wi-fi network connected
to be exploited so anyone with access to that network can do it.
I have not tested if there are limitations on Internet or in big WANs.
The remote controller feature is enabled by default like all the other
services (over 40 TCP ports opened on the TV).


#######################################################################

=======
2) Bugs
=======


When the controller packet is received on the device it displays a
message on the screen for telling the user that a new "remote" device
has been found and he must select "allow" or "deny" to continue.

The message includes also the name and MAC address specified in the
received packet, they are just normal strings (there is even a field
containing the IP address for unknown reasons).


-------------------
A] Endless restarts
-------------------

The controller packet contains a string field used for the name of the
controller.
When the user selects one of the two choices (allow/deny) available
after having received an invalid name string (for example containing
line feed and other invalid chars) the device enters in the following
endless loop:
- for about 5 seconds everything seems to work correctly
- then the TV can be no longer controlled manually (both the TV remote
  controller and the TV panel become slow and then completely
  inactive), it just doesn't accept inputs
- after other 5 seconds the TV restarts automatically
- this situation will continue forever

During these continuous reboots it's not even possible to reset the
device (for example the "EXIT" button for 15 seconds can't work in
this state) or doing other operations allowed by the normal users
without affecting the warranty.

This is not a simple temporary Denial of Service, the TV is just
impossible to be used and reset so it's necessary the manual
intervention of the technical assistance that will reset it via the
service mode (luckily the 5 seconds of activity are enough to reach the
reset option).

The user can avoid the exploiting of the vulnerability by pushing the
EXIT button on the controller when the message with allow/deny is
displayed on the screen.


---------------------------
B] Possible buffer-overflow
---------------------------

By setting some fields like the MAC address to a long string it's
possible to crash the device, probably due to a buffer-overflow
vulnerability (just my guess).


No additional analysis is possible because I can't debug the device and
sincerely I'm not interested in killing my poor TV just for finding
other bugs and understanding them :)


#######################################################################

===========
3) The Code
===========


http://aluigi.org/poc/samsux_1.zip
https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/18751.zip


#######################################################################

======
4) Fix
======


No fix because I wanted to report the problems to Samsung but an e-mail
address doesn't exist for these types of bugs (support@samsung.com is
not available).
It would have been useful also for having more details about the
problems and knowing if all or only some devices are affected but no
way.


#######################################################################