source: https://www.securityfocus.com/bid/1844/info

A buffer overflow exists in the Intel InBusiness eMail Station, a dedicated email device. When attempting to establish a connection, the username submitted to the device is not properly filtered for length. By supplying a string for USER of approximately 620 characters in length, it is possible for a remote attacker to overflow the relevant buffer. The device will halt in response, requiring the unit to be powered down and restarted. In addition to this denial of service, an attacker sufficiently familiar with the hardware architecture and firmware of this platform may, potentially, be able to exploit this overflow to place malicious machine code on the stack, permitting interference with or modification of the device's software, interception of messages, or another compromise of the unit's normal function.

[foo@bar]$ telnet mailstation 110
Trying mailstation...
Connected to mailstation.
Escape character is '^]'.
+OK Pop server at mailstation starting. <2831812.972049732@mail>
user [buffer]

where [buffer] is appx. 620 chars of your own choice.(tried A and %, expect
all to work)

Symptoms: The box(a nice little piece of hardware with built-in harddrive
and all) will stop responding, and needs a power cycle to restore function.