source: https://www.securityfocus.com/bid/19006/info

D-Link wired and wireless routers are prone to a buffer-overflow vulnerability because these devices fail to properly bounds-check user-supplied input before copying it to an insufficiently sized memory buffer.

Successful exploits can allow remote attackers to execute arbitrary machine code in the context of the affected device.

Attackers can exploit this issue by sending a request of the form:

M-SEARCH <800 byte string> HTTP/1.0

to UDP port 1900.