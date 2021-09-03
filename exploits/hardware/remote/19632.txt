source: https://www.securityfocus.com/bid/806/info


Certain versions of the Tektronix PhaserLink printer ship with a webserver designed to help facilitate configuration of the device. This service is essentially administrator level access as it can completely modify the system characteristics, restart the machine, asign services etc.

In at least one version of this printer there are a series of undocumented URL's which will allow remote users to retrieve the administrator password. Once the password is obtained by the user, they can manipulate the printer in any way they see fit.

To obtain the administrator password:

http://printername/ncl_items.html?SUBJECT=2097