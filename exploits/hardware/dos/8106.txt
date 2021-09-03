LUNOSEC ADVISORY

Synopsis: Denial of Service condition in Netgear's WGR614v9 Wireless Router

Firmware version tested: v1.2.2_14.0.13NA (LATEST)
Firmware version tested: WNR834Bv2 v2.0.8_2.0.8 # GTADarkDude tested

Proof of Concept:

Appending a question mark to the router's internal IP address after
the forward slash. e.g., http://192.168.1.1/? results in a denial of
service condition where the http server dies and the administrative
interface is no longer available until after a device reboot.

found: fabrizio siciliano (staticrez)

# milw0rm.com [2009-02-25]