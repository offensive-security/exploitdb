source: https://www.securityfocus.com/bid/2689/info

The Catalyst series switch is a scalable, high performance layers 2 and 3 switch manufactured by Cisco Systems. The Catalyst series ranges in size, and is designed for use in organizations sized from small business to large enterprise.

A problem with the switch firmware could allow a Denial of Service to legitimate users of network resources. Upon booting the switch with SNMP disabled, the service does not handle normal requests. However, by sending an empty UDP packet to the SNMP port, the switch ceases operating.

This problem makes it possible for a remote user to deny service to legitimate users of the switch.

https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/20824.tgz