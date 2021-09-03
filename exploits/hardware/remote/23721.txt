source: https://www.securityfocus.com/bid/9688/info

Linksys WAP55AG appliance has been reported prone to an insecure default configuration vulnerability.

It has been reported that all SNMP MIB (Management Information Base) community strings, even read/write strings may be disclosed to a remote attacker if the attacker makes certain queries to the affected appliance.

An attacker may disclose sensitive information in this manner. Although unconfirmed, it may also be possible for the attacker to manipulate the appliance configuration through writeable strings.

Querying OID:
1.3.6.1.4.1.3955.2.1.13.1.2.

1.3.6.1.4.1.3955.2.1.13.1.2.1 = STRING: "public"
1.3.6.1.4.1.3955.2.1.13.1.2.2 = STRING: "private"