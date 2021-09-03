Product Name: Netgear DG632 Router
Vendor: http://www.netgear.com
Date: 15 June, 2009
Author: tom@tomneaves.co.uk < tom@tomneaves.co.uk >
Original URL: http://www.tomneaves.co.uk/Netgear_DG632_Remote_DoS.txt
Discovered: 18 November, 2006
Disclosed: 15 June, 2009

I. DESCRIPTION

The Netgear DG632 router has a web interface which runs on port 80.  This
allows an admin to login and administer the device's settings.  However,
a Denial of Service (DoS) vulnerability exists that causes the web interface
to crash and stop responding to further requests.

II. DETAILS

Within the "/cgi-bin/" directory of the administrative web interface exists a
file called "firmwarecfg".  This file is used for firmware upgrades.  A HTTP POST
request for this file causes the web server to hang.  The web server will stop
responding to requests and the administrative interface will become inaccessible
until the router is physically restarted.

While the router will still continue to function at the network level, i.e. it will
still respond to ICMP echo requests and issue leases via DHCP, an administrator will
no longer be able to interact with the administrative web interface.

This attack can be carried out internally within the network, or over the Internet
if the administrator has enabled the "Remote Management" feature on the router.

Affected Versions: Firmware V3.4.0_ap (others unknown)

III. VENDOR RESPONSE

12 June, 2009 - Contacted vendor.
15 June, 2009 - Vendor responded.  Stated the DG632 is an end of life product and is no
longer supported in a production and development sense, as such, there will be no further
firmware releases to resolve this issue.

IV. CREDIT

Discovered by Tom Neaves

# milw0rm.com [2009-06-15]